package celeritas

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CloudyKit/jet/v6"
	"github.com/alexedwards/scs/v2"
	"github.com/dgraph-io/badger/v3"
	"github.com/emirkosuta/celeritas/cache"
	"github.com/emirkosuta/celeritas/jwt"
	"github.com/emirkosuta/celeritas/mailer"
	"github.com/emirkosuta/celeritas/render"
	"github.com/emirkosuta/celeritas/session"
	"github.com/emirkosuta/celeritas/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/gomodule/redigo/redis"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
)

const version = "1.0.0"

var myRedisCache *cache.RedisCache
var myBadgerCache *cache.BadgerCache
var redisPool *redis.Pool
var badgerConn *badger.DB

type Celeritas struct {
	AppName       string
	Debug         bool
	Version       string
	ErrorLog      *log.Logger
	InfoLog       *log.Logger
	RootPath      string
	Routes        *chi.Mux
	Render        *render.Render
	JetViews      *jet.Set
	Session       *scs.SessionManager
	DB            Database
	config        config
	EncryptionKey string
	JwtToken      jwt.JwtToken
	Cache         cache.Cache
	Scheduler     *cron.Cron
	Storage       storage.Storage
	PublicStorage storage.Storage
	Mail          mailer.Mail
	Server        Server
	Frontend      Frontend
	moduleName    string
}

type Server struct {
	ServerName string
	Port       string
	Secure     bool
	URL        string
}

type Frontend struct {
	URL string
}

type config struct {
	port        string
	renderer    string
	cookie      cookieConfig
	sessionType string
	database    databaseConfig
	redis       redisConfig
}

func (c *Celeritas) New(rootPath string) error {
	validate = validator.New()

	pathConfig := initPaths{
		rootPath:    rootPath,
		folderNames: []string{"handlers", "migrations", "views", "mail", "data", "public", "tmp", "logs", "middleware", "storage", "storage/public"},
	}

	err := c.Init(pathConfig)
	if err != nil {
		return err
	}

	err = c.checkDotEnv(rootPath)
	if err != nil {
		return err
	}

	err = godotenv.Load(rootPath + "/.env")
	if err != nil {
		return err
	}

	c.Scheduler = cron.New()

	infoLog, errorLog := c.startLoggers()

	c.InfoLog = infoLog
	c.ErrorLog = errorLog
	c.Debug, _ = strconv.ParseBool(os.Getenv("DEBUG"))
	c.Version = version
	c.RootPath = rootPath
	c.Routes = c.routes().(*chi.Mux)
	c.config = config{
		port:     os.Getenv("PORT"),
		renderer: os.Getenv("RENDERER"),
		database: databaseConfig{
			database: os.Getenv("DATABASE_TYPE"),
			dsn:      c.BuildDSN(),
		},
		cookie: cookieConfig{
			name:     os.Getenv("COOKIE_NAME"),
			lifetime: os.Getenv("COOKIE_LIFETIME"),
			persist:  os.Getenv("COOKIE_PERSIST"),
			secure:   os.Getenv("COOKIE_SECURE"),
			domain:   os.Getenv("COOKIE_DOMAIN"),
		},
		sessionType: os.Getenv("SESSION_TYPE"),
		redis: redisConfig{
			host:     os.Getenv("REDIS_HOST"),
			password: os.Getenv("REDIS_PASSWORD"),
			prefix:   os.Getenv("REDIS_PREFIX"),
		},
	}

	jwtTokenDuration, err := time.ParseDuration(os.Getenv("JWT_ACCESS_TOKEN_EXPIRY"))
	if err != nil {
		return err
	}
	jwtRefreshDuration, err := time.ParseDuration(os.Getenv("JWT_REFRESH_TOKEN_EXPIRY"))
	if err != nil {
		return err
	}

	c.JwtToken = jwt.JwtToken{
		JwtTokenTimeExp:        jwtTokenDuration,
		JwtRefreshTokenTimeExp: jwtRefreshDuration,
		RSAPrivate:             os.Getenv("JWT_RSA_PRIVATE"),
		RSAPublic:              os.Getenv("JWT_RSA_PUBLIC"),
	}

	secure := true
	if strings.ToLower(os.Getenv("SECURE")) == "false" {
		secure = false
	}

	c.Server = Server{
		ServerName: os.Getenv("SERVER_NAME"),
		Port:       os.Getenv("PORT"),
		Secure:     secure,
		URL:        os.Getenv("APP_URL"),
	}

	c.Frontend = Frontend{
		URL: os.Getenv("FRONTEND_URL"),
	}

	// connect to database
	if os.Getenv("DATABASE_TYPE") != "" {
		db, err := c.OpenDB(os.Getenv("DATABASE_TYPE"), c.BuildDSN())
		if err != nil {
			c.ErrorLog.Println(err)
			os.Exit(1)
		}
		c.DB = Database{
			DatabaseType: os.Getenv("DATABASE_TYPE"),
			Pool:         db,
		}
	}

	if os.Getenv("CACHE") == "redis" || os.Getenv("SESSION_TYPE") == "redis" {
		myRedisCache = c.createClientRedisCache()
		c.Cache = myRedisCache
		redisPool = myRedisCache.Conn
	}

	if os.Getenv("CACHE") == "badger" {
		myBadgerCache = c.createClientBadgerCache()
		c.Cache = myBadgerCache
		badgerConn = myBadgerCache.Conn

		_, err = c.Scheduler.AddFunc("@daily", func() {
			_ = myBadgerCache.Conn.RunValueLogGC(0.7)
		})
		if err != nil {
			return err
		}
	}

	// create session
	sess := session.Session{
		CookieLifetime: c.config.cookie.lifetime,
		CookiePersist:  c.config.cookie.persist,
		CookieName:     c.config.cookie.name,
		SessionType:    c.config.sessionType,
		CookieDomain:   c.config.cookie.domain,
	}

	switch c.config.sessionType {
	case "redis":
		sess.RedisPool = myRedisCache.Conn
	case "postgres", "postgresql", "mysql", "mariadb":
		sess.DBPool = c.DB.Pool
	}

	c.Session = sess.InitSession()
	c.EncryptionKey = os.Getenv("KEY")

	if c.Debug {
		var views = jet.NewSet(
			jet.NewOSFileSystemLoader(fmt.Sprintf("%s/views", rootPath)),
			jet.InDevelopmentMode(),
		)
		c.JetViews = views
	} else {
		var views = jet.NewSet(
			jet.NewOSFileSystemLoader(fmt.Sprintf("%s/views", rootPath)),
		)
		c.JetViews = views
	}

	c.createRenderer()

	c.Storage = c.createStorage()
	c.PublicStorage = c.createPublicStorage()
	c.Mail = c.createMailer()
	go c.Mail.ListenForMail()

	return nil
}

func (c *Celeritas) Init(p initPaths) error {
	root := p.rootPath
	for _, path := range p.folderNames {
		err := c.CreateDirIfNotExist(root + "/" + path)
		if err != nil {
			return err
		}
	}
	return nil
}

// start the webserver
func (c *Celeritas) ListenAndServe() {
	// Create a file server to serve static files
	fs := http.FileServer(http.Dir(c.Storage.BaseDir) + "/public")

	// Use the FileServer middleware to serve files from the static directory
	c.Routes.Handle("/public/*", http.StripPrefix("/public/", fs))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", os.Getenv("PORT")),
		ErrorLog:     c.ErrorLog,
		Handler:      c.Routes,
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 600 * time.Second,
	}

	if c.DB.Pool != nil {
		defer c.DB.Pool.Close()
	}

	if badgerConn != nil {
		defer badgerConn.Close()
	}

	if redisPool != nil {
		defer redisPool.Close()
	}

	c.InfoLog.Printf("Listening on port %s", os.Getenv("PORT"))
	err := srv.ListenAndServe()
	c.ErrorLog.Fatal(err)
}

func (c *Celeritas) checkDotEnv(path string) error {
	err := c.CreateFileIfNotExist(fmt.Sprintf("%s/.env", path))
	if err != nil {
		return err
	}
	return nil
}

func (c *Celeritas) startLoggers() (*log.Logger, *log.Logger) {
	var infoLog *log.Logger
	var errorLog *log.Logger

	infoLog = log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog = log.New(os.Stdout, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	return infoLog, errorLog
}

func (c *Celeritas) createRenderer() {
	myRenderer := render.Render{
		Renderer: c.config.renderer,
		RootPath: c.RootPath,
		Port:     c.config.port,
		JetViews: c.JetViews,
		Session:  c.Session,
	}

	c.Render = &myRenderer
}

func (c *Celeritas) createMailer() mailer.Mail {
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	m := mailer.Mail{
		Domain:      os.Getenv("MAIL_DOMAIN"),
		Templates:   c.RootPath + "/mail",
		Host:        os.Getenv("SMTP_HOST"),
		Port:        port,
		Username:    os.Getenv("SMTP_USERNAME"),
		Password:    os.Getenv("SMTP_PASSWORD"),
		Encryption:  os.Getenv("SMTP_ENCRYPTION"),
		FromName:    os.Getenv("FROM_NAME"),
		FromAddress: os.Getenv("FROM_ADDRESS"),
		Jobs:        make(chan mailer.Message, 20),
		Results:     make(chan mailer.Result, 20),
		API:         os.Getenv("MAILER_API"),
		APIKey:      os.Getenv("MAILER_KEY"),
		APIUrl:      os.Getenv("MAILER_URL"),
	}
	return m
}

func (c *Celeritas) createStorage() storage.Storage {
	storageClient := storage.Storage{
		BaseDir: filepath.Join(c.RootPath, os.Getenv("STORAGE_PATH")),
	}
	return storageClient
}

func (c *Celeritas) createPublicStorage() storage.Storage {
	storageClient := storage.Storage{
		BaseDir: filepath.Join(c.RootPath, os.Getenv("STORAGE_PATH")+"/public"),
	}
	return storageClient
}

func (c *Celeritas) createClientRedisCache() *cache.RedisCache {
	cacheClient := cache.RedisCache{
		Conn:   c.createRedisPool(),
		Prefix: c.config.redis.prefix,
	}
	return &cacheClient
}

func (c *Celeritas) createClientBadgerCache() *cache.BadgerCache {
	cacheClient := cache.BadgerCache{
		Conn: c.createBadgerConn(),
	}
	return &cacheClient
}

func (c *Celeritas) createRedisPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:     50,
		MaxActive:   10000,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp",
				c.config.redis.host,
				redis.DialPassword(c.config.redis.password))
		},

		TestOnBorrow: func(conn redis.Conn, t time.Time) error {
			_, err := conn.Do("PING")
			return err
		},
	}
}

func (c *Celeritas) createBadgerConn() *badger.DB {
	db, err := badger.Open(badger.DefaultOptions(c.RootPath + "/tmp/badger"))
	if err != nil {
		return nil
	}
	return db
}

func (c *Celeritas) BuildDSN() string {
	var dsn string

	switch os.Getenv("DATABASE_TYPE") {
	case "postgres", "postgresql":
		dsn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s timezone=UTC connect_timeout=5",
			os.Getenv("DATABASE_HOST"),
			os.Getenv("DATABASE_PORT"),
			os.Getenv("DATABASE_USER"),
			os.Getenv("DATABASE_NAME"),
			os.Getenv("DATABASE_SSL_MODE"),
		)
		if os.Getenv("DATABASE_PASS") != "" {
			dsn = fmt.Sprintf("%s password=%s", dsn, os.Getenv("DATABASE_PASS"))
		}

	default:

	}

	return dsn
}
