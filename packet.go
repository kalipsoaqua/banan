package web

import (
	"bytes"
	"encoding/json"
	tmpl "html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"bufio"
	"crypto/tls"
	"fmt"
	"net/url"
)

/*
	FuncApi - struct function
	pattern - name function
	types - type function (GET, PUT, DELETE, POST)
	handle - handle function
	arg    - list arguments
*/

const (
	NO_INDEX = 1 // Не использовать основной шаблон
	CROSS    = 2 // Пустая константа для кросдомена
)

type FuncApi struct {
	pattern *regexp.Regexp
	types   string
	handle  interface{}
	arg     []interface{}
}

type Params []string

type ServCookie struct {
	sync.Mutex
	db map[string]*ClientCookie
}

type RunApi struct {
	functionRun *FuncApi
	flagRun     bool
	ftype       []reflect.Value
	response    http.ResponseWriter
	request     *http.Request
	config      Config
	cookie      *ServCookie
	sync.Mutex
}

type HandleFunc func(...interface{})

type Directory struct {
	Name string
	Path string
}

type MimeTypes struct {
	Ext      string
	MimeType string
}

type Config struct {
	Static       Directory
	Template     Directory
	Extension    string
	Layer        string
	Mime         []MimeTypes
	Funcs        []tmpl.FuncMap
	Cache        bool
	CookieSecure bool
	Logger       *log.Logger
}

type Banan struct {
	funcApi   []*FuncApi
	prefix    string
	ftype     []reflect.Value
	config    Config
	cookie    ServCookie
	basicAuth bool
	basicUser map[string]string
	basicMsg  string
}

type ClientCookie struct {
	argv       map[string]interface{}
	dateUpdate int64
	life       int64
}

var memtype = map[string]string{
	"css":  "text/css",
	"js":   "text/javascript",
	"html": "text/html",
	"jpg":  "image/jpeg",
	"png":  "image/png",
	"gif":  "image/gif",
	"txt":  "text/plain",
}

type CacheFile struct {
	Buffer     *bytes.Buffer
	TimeModify time.Time
}

var (
	bufferFile  map[string]*CacheFile
	mutex       sync.Mutex
	OsSeparator string = "/"
	logCanal    chan string
)

func (f *Banan) logging() {
	for msg := range logCanal {
		f.config.Logger.Println(msg)
	}
}

func Default() *Banan {
	f := Banan{}
	if runtime.GOOS == "windows" {
		OsSeparator = "\\"
	}
	f.funcApi = make([]*FuncApi, 0)
	bufferFile = make(map[string]*CacheFile)
	logCanal = make(chan string, 10000)

	f.ftype = make([]reflect.Value, 0)
	f.cookie.db = make(map[string]*ClientCookie)
	f.config = Config{
		Extension: "html",
		Layer:     "index.html",
		Static:    Directory{"public", "public"},
		Template:  Directory{"template", "template"},
		Logger:    log.New(os.Stderr, "", log.LstdFlags),
	}
	f.basicUser = make(map[string]string)
	go f.logging()
	return &f
}

func (f *Banan) Work() string {
	argsWithProg := os.Args
	tmp_arr := strings.Split(argsWithProg[0], OsSeparator)
	return strings.Join(tmp_arr[:len(tmp_arr)-1], OsSeparator) + OsSeparator
}

func (f *Banan) Option(c Config) {
	if c.Layer != "" {
		f.config.Layer = c.Layer
	}
	if c.Extension != "" {
		f.config.Extension = c.Extension
	}
	if c.Static.Name != "" {
		f.config.Static = c.Static
		f.config.Static.Path = strings.Replace(f.config.Static.Path, "/", OsSeparator, -1)
	}

	if c.Template.Name != "" {
		f.config.Template = c.Template
		f.config.Template.Path = strings.Replace(f.config.Template.Path, "/", OsSeparator, -1)
	}
	if c.Cache {
		f.config.Cache = c.Cache
	}
	for _, mimeValue := range c.Mime {
		memtype[mimeValue.Ext] = mimeValue.MimeType
	}
	f.config.Funcs = c.Funcs
}

func (f *Banan) Use(m ...interface{}) {
	for _, tmp := range m {
		f.ftype = append(f.ftype, reflect.ValueOf(tmp))
	}
}

func (f *Banan) Route(pref string) *Banan {
	f.prefix = pref
	return f
}

func (f *Banan) Run(addr string, cert ...string) {
	fileList := []string{}
	filepath.Walk(f.config.Template.Path, func(path string, g os.FileInfo, err error) error {
		if err == nil {
			if !g.IsDir() {
				if strings.HasSuffix(path, f.config.Extension) {
					fileList = append(fileList, strings.Replace(path, f.config.Template.Path+OsSeparator, "", -1))
				}
			}
		}
		return nil
	})
	for _, file := range fileList {
		template := strings.Replace(file, "."+f.config.Extension, "", -1)
		data, err := ioutil.ReadFile(f.config.Template.Path + OsSeparator + file)
		if err != nil {
			logCanal <- "ERROR = " + err.Error()
			return
		}
		logCanal <- fmt.Sprint("load template [", template, "]")
		bufferFile[template] = &CacheFile{bytes.NewBuffer([]byte(data)), time.Now()}

	}

	logCanal <- fmt.Sprint("Run server to ", addr)
	srv := &http.Server{
		Addr:    addr,
		Handler: f,
		//ReadTimeout: 1 * time.Second,
		//WriteTimeout: 1 * time.Second,
	}
	if len(cert) > 0 {
		srv.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
		}
		log.Fatal(srv.ListenAndServeTLS(cert[0], cert[1]))
	} else {
		log.Fatal(srv.ListenAndServe())
	}

}

func isMethod(method string, req *http.Request) bool {

	if method == req.Method {
		return true
	}

	if req.Method == "OPTIONS" {

		if method == req.Header.Get("Access-Control-Request-Method") {
			return true
		}

	}

	return false
}

func (f *Banan) BasicAuth(user map[string]string, msg string) {
	f.basicAuth = true
	f.basicUser = user
	f.basicMsg = msg
}

func (f *Banan) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	if f.basicAuth {
		res.Header().Set("WWW-Authenticate", `Basic realm="`+f.basicMsg+`"`)

		username, password, authOK := req.BasicAuth()
		if authOK == false {
			http.Error(res, "Not authorized", 401)
			return
		}
		userOk := false
		for u, p := range f.basicUser {
			if username == u && password == p {
				userOk = true
			}
		}

		if !userOk {
			http.Error(res, "Not authorized", 401)
			return
		}

	}

	flagok := false
	logCanal <- fmt.Sprint("[", req.RemoteAddr, "] ", req.Proto, " "+req.Method+" ", req.URL, " ", req.Header)

	if !strings.HasPrefix(req.URL.Path, "/"+f.config.Static.Name) {

		if req.Method == "OPTIONS" {
			res.Header().Set("Content-Type", "multipart/form-data")
			res.Header().Set("Access-Control-Allow-Origin", "*")
			res.Header().Set("Access-Control-Allow-Headers", "Content-Type,Accept")
			return
		}

		for key, fun := range f.funcApi {
			if fun.pattern.MatchString(req.URL.Path) && isMethod(fun.types, req) {
				ftype := make([]reflect.Value, 0)
				ftype = append(ftype, f.ftype...)
				ftype = append(ftype,
					reflect.Indirect(reflect.ValueOf(&res)),
					reflect.ValueOf(req),
					reflect.ValueOf(Params(fun.pattern.FindStringSubmatch(req.URL.Path)[1:])),
				)

				a := &RunApi{
					functionRun: f.funcApi[key],
					flagRun:     true,
					ftype:       ftype,
					response:    res,
					request:     req,
					config:      f.config,
					cookie:      &f.cookie,
				}

				a.setId()
				flagok = true
				ch := make(chan bool)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							panic("Recovered in func")
						}
					}()

					ftype = append(ftype, reflect.ValueOf(a))

					//		fn := reflect.Indirect(reflect.ValueOf(&c.functionRun.handle)).Elem()
					fn := reflect.ValueOf(f.funcApi[key].handle)

					argvCall := make([]reflect.Value, 0)

					for _, funcArgv := range f.funcApi[key].arg {
						for key2, handlerArgv := range ftype {
							if funcArgv == handlerArgv.Type() {
								argvCall = append(argvCall, ftype[key2])
							}
						}
					}

					fn.Call(argvCall)

					ch <- true
				}()
				select {
				case <-ch:
					break
				case <-time.After(3 * time.Second):
					break
				}

				break
			}
		}
	}

	if !flagok {
		url_path := strings.Replace(req.URL.Path, "/", OsSeparator, -1)
		if strings.Contains(url_path, f.config.Static.Name+OsSeparator) {
			var ok bool
			if _, ok = bufferFile[url_path]; (!ok && f.config.Cache) || !f.config.Cache {
				kk := strings.Split(url_path, f.config.Static.Name)
				dataByte, err := ioutil.ReadFile(f.config.Static.Path + strings.Join(kk[1:], OsSeparator))
				if err != nil {
					logCanal <- fmt.Sprint("[", req.RemoteAddr, "] ERROR open file ", req.URL.Path)
					res.WriteHeader(404)
				}
				mutex.Lock()
				bufferFile[req.URL.Path] = &CacheFile{bytes.NewBuffer(dataByte), time.Now()}
				mutex.Unlock()
			}
			/*
				types := "application/octet-stream"
				for ext, mtypes := range memtype {
					if strings.HasSuffix(req.URL.Path, ext) {
						types = mtypes
						res.Header().Set("Cache-Control", "max-age=3600, must-revalidate")
					}
				}
				res.Header().Set("Content-Type", types)
				res.Write(bufferFile[req.URL.Path].Bytes())
			*/
			http.ServeContent(res, req, req.URL.Path, bufferFile[req.URL.Path].TimeModify, strings.NewReader(bufferFile[req.URL.Path].Buffer.String()))
		} else {
			logCanal <- fmt.Sprint("[", req.RemoteAddr, "] ERROR path(1) ", req.URL.Path)
			res.WriteHeader(404)
		}
	}

}

func (f *Banan) Get(filter string, function interface{}) {
	f.appHandler("GET", filter, function)
}

func (f *Banan) Post(filter string, function interface{}) {
	f.appHandler("POST", filter, function)
}

func (f *Banan) Put(filter string, function interface{}) {
	f.appHandler("PUT", filter, function)
}

func (f *Banan) Delete(filter string, function interface{}) {
	f.appHandler("DELETE", filter, function)
}

func (f *Banan) appHandler(method, filter string, function interface{}) {
	funcArg := make([]interface{}, 0)
	for i := 0; i < reflect.ValueOf(function).Type().NumIn(); i++ {
		funcArg = append(funcArg, reflect.ValueOf(function).Type().In(i))
	}
	//fmt.Println("^" + strings.Replace(f.prefix+filter, ":param", `(.*?)[\/]`, -1) + "$")
	filter = strings.Replace(filter, "/", "\\/", -1)
	f.funcApi = append(f.funcApi, &FuncApi{
		types:   method,
		pattern: regexp.MustCompile("^" + strings.Replace(f.prefix+filter, ":param", `(.*?)[\/]{0,1}`, -1) + "$"),
		handle:  function,
		arg:     funcArg,
	})
}

func (c *RunApi) JSON(h interface{}, cross ...int) {
	result, err := json.Marshal(h)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		c.response.WriteHeader(500)
		return
	}
	c.response.Header().Set("Content-Type", "application/json")
	if len(cross) > 0 {
		c.response.Header().Set("Access-Control-Allow-Origin", "*")
		c.response.Header().Set("Access-Control-Allow-Headers", "Content-Type,Accept")
	}
	c.response.Write(result)
}

func (c *RunApi) TXT(h interface{}, cross ...int) {
	c.response.Header().Set("Content-Type", "text/plan")
	if len(cross) > 0 {
		c.response.Header().Set("Access-Control-Allow-Origin", "*")
		c.response.Header().Set("Access-Control-Allow-Headers", "Content-Type,Accept")
	}
	switch h.(type) {
	case string:
		txt := h.(string)
		c.response.Write([]byte(txt))
	case []byte:
		c.response.Write(h.([]byte))
	}
}

func (c *RunApi) XML(h interface{}) {
	c.response.Header().Set("Content-Type", "text/xml")

	switch h.(type) {
	case string:
		txt := h.(string)
		c.response.Write([]byte(txt))
	case []byte:
		c.response.Write(h.([]byte))
	}
}

func genChar() string {
	rand.Seed(time.Now().Unix())
	mm := make([]byte, 0)
	for i := 0; i < 32; i++ {
		mm = append(mm, 48+byte(rand.Intn(10)))
	}
	return string(mm)
}

func (c *RunApi) parseCookie() map[string]string {
	tmp := make(map[string]string)
	cookie := c.request.Header.Get("Cookie")
	if cookie != "" {
		tmp_cookie := strings.Split(cookie, ";")
		for _, value := range tmp_cookie {
			tmp_p := strings.Split(value, "=")
			if len(tmp_p) > 1 {
				tmp[tmp_p[0]] = strings.Join(tmp_p[1:], "")
			}
		}

	}
	return tmp
}

func (c *RunApi) createKeyCookie(key string) {
	c.cookie.Lock()
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered in f", r)
		}
		c.cookie.Unlock()
	}()
	if _, ok := c.cookie.db[key]; !ok {
		c.cookie.db[key] = &ClientCookie{
			argv:       make(map[string]interface{}),
			dateUpdate: time.Now().Unix(),
			life:       2 * 24 * 3600,
		}

	}
}

func (c *RunApi) setId() string {
	//Secure only https
	key := genChar()
	pair := c.parseCookie()
	if pair["session_id"] != "" {
		key = pair["session_id"]
	}

	c.createKeyCookie(key)

	if pair["session_id"] == "" {
		c.response.Header().Set("Set-Cookie", "session_id="+key+"; HttpOnly; path=/;")
	}
	return key
}

func (c *RunApi) Set(name string, value interface{}) {
	pair := c.parseCookie()
	c.cookie.Lock()
	defer c.cookie.Unlock()
	if pair["session_id"] != "" {
		if _, ok := c.cookie.db[pair["session_id"]]; ok {
			c.cookie.db[pair["session_id"]].argv[name] = value
			return
		}
	}

	session_id := c.setId()
	c.cookie.db[session_id].argv[name] = value
	c.cookie.db[session_id].dateUpdate = time.Now().Unix()
}

func (c *RunApi) Delete(name string) {
	pair := c.parseCookie()
	c.cookie.Lock()
	defer c.cookie.Unlock()
	if pair["session_id"] != "" {
		if _, ok := c.cookie.db[pair["session_id"]]; ok {
			delete(c.cookie.db[pair["session_id"]].argv, name)
		}
	}
}

func (c *RunApi) Close() {
	c.cookie.Lock()
	defer c.cookie.Unlock()
	pair := c.parseCookie()
	if pair["session_id"] != "" {
		delete(c.cookie.db, pair["session_id"])
		//c.response.Header().Set("Set-Cookie", "HttpOnly; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	}
}

func (c *RunApi) Get(name string) interface{} {
	c.cookie.Lock()
	defer c.cookie.Unlock()
	pair := c.parseCookie()
	if pair["session_id"] != "" {
		if value, ok := c.cookie.db[pair["session_id"]]; ok {
			if valueOut, ok := value.argv[name]; ok {
				c.cookie.db[pair["session_id"]].dateUpdate = time.Now().Unix()
				return valueOut
			}
		}
	}
	return nil
}

func (c *RunApi) RemoteIp() string {
	return strings.Split(c.request.RemoteAddr, ":")[0]
}

func (c *RunApi) Header() http.Header {
	return c.request.Header
}

func (c *RunApi) Body() []byte {
	defer c.request.Body.Close()
	body, _ := ioutil.ReadAll(c.request.Body)
	return body
}

func (c *RunApi) Form() url.Values {
	tmp := url.Values{}
	err := c.request.ParseForm()
	if err == nil {

		for vv, kk := range c.request.PostForm {
			tmp.Add(vv, kk[0])
		}
		for vv, kk := range c.request.Form {
			if _, ok := tmp[vv]; !ok {
				tmp.Add(vv, kk[0])
			}
		}

	}
	return tmp
}

func (c *RunApi) Download(file string) {
	tmp := strings.Split(file, "/")
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	if len(tmp) > 0 {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] DOWNLOAD START ", file)
		http.ServeContent(c.response, c.request, tmp[len(tmp)-1], time.Now(), f)
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] DOWNLOAD STOP ", file)
	}
}

func (c *RunApi) Redirect(url string) {
	http.Redirect(c.response, c.request, url, http.StatusFound)
}

func (c *RunApi) HTML(template string, h interface{}, arg ...int) {
	body := ""

	template = strings.Replace(template, "/", OsSeparator, -1)
	if len(arg) == 0 {
		index := strings.Replace(c.config.Layer, "."+c.config.Extension, "", 1)
		body = strings.Replace(bufferFile[index].Buffer.String(), "{{ current }}", bufferFile[template].Buffer.String(), 1)
	} else {
		if arg[0] == NO_INDEX {
			body = bufferFile[template].Buffer.String()
		}
	}
	t := tmpl.New("foo")

	for _, ftmpl := range c.config.Funcs {
		t = t.Funcs(ftmpl)
	}
	t, err := t.Parse(body)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return
	}

	c.response.Header().Set("Content-Type", "text/html")
	err = t.Execute(c.response, h)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return
	}
}

func (c *RunApi) BuildHTML(template string, h interface{}, arg ...int) []byte {

	var b bytes.Buffer

	body := ""

	template = strings.Replace(template, "/", OsSeparator, -1)
	if len(arg) == 0 {
		index := strings.Replace(c.config.Layer, "."+c.config.Extension, "", 1)
		body = strings.Replace(bufferFile[index].Buffer.String(), "{{ current }}", bufferFile[template].Buffer.String(), 1)
	} else {
		if arg[0] == NO_INDEX {
			if v, ok := bufferFile[template]; ok {
				body = v.Buffer.String()
			}
		}
	}

	t := tmpl.New("foo")

	for _, ftmpl := range c.config.Funcs {
		t = t.Funcs(ftmpl)
	}
	t, err := t.Parse(body)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return []byte{}
	}
	w := bufio.NewWriter(&b)
	err = t.Execute(w, h)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return []byte{}
	}
	w.Flush()
	return b.Bytes()
}

func (c *RunApi) TemplateHTML(template string, h interface{}, arg ...int) []byte {

	var b bytes.Buffer

	body, _ := ioutil.ReadFile(template)

	t := tmpl.New("foo")

	for _, ftmpl := range c.config.Funcs {
		t = t.Funcs(ftmpl)
	}
	t, err := t.Parse(string(body))
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return []byte{}
	}
	w := bufio.NewWriter(&b)
	err = t.Execute(w, h)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return []byte{}
	}
	w.Flush()
	return b.Bytes()
}

func (c *RunApi) IHTML(index string, h interface{}) {

	t := tmpl.New("foo")

	for _, ftmpl := range c.config.Funcs {
		t = t.Funcs(ftmpl)
	}
	t, err := t.Parse(index)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return
	}

	c.response.Header().Set("Content-Type", "text/html")
	err = t.Execute(c.response, h)
	if err != nil {
		logCanal <- fmt.Sprint("[", c.request.RemoteAddr, "] ERROR = ", err)
		return
	}
}

func (c *RunApi) run() {
	if c.flagRun {
		c.ftype = append(c.ftype, reflect.ValueOf(c))
		//		fn := reflect.Indirect(reflect.ValueOf(&c.functionRun.handle)).Elem()
		fn := reflect.ValueOf(c.functionRun.handle)

		argvCall := make([]reflect.Value, 0)

		for _, funcArgv := range c.functionRun.arg {
			for key, handlerArgv := range c.ftype {
				if funcArgv == handlerArgv.Type() {
					argvCall = append(argvCall, c.ftype[key])
				}
			}
		}

		fn.Call(argvCall)

	}
}
