# banan


*Маленький **web**  framework* 

Директория для статики (css, js, ....) - public
Директория для template (html) - template


Функция **Default()** - инстализация  

Функция **Use(context)** - добавить контекст (например базу данных)

Функция **Middle(func)** - добавить функцию middle для обработки до роутинга

Функция **Get(pattern, handler)**,**Post(pattern, handler)**,**Put(pattern, handler)**,**Delete(pattern, handler)** - роутинг по url, pattern - путь по которому надо запустить, тот иkи иной handler

Функция **Run(listen, [cert])** - запуск 

**RunAPI**
1. JSON(data, [CROSS])
1. HTML(template, data, [NOINDEX])
1. BuildHTML(template, data, [NOINDEX]) []byte
1. TemplateHTML(template, data, [NOINDEX]) []byte
1. IHTML(htmlString, data)
1. TXT(txt, [CROSS])
1. Form() - переданные данные GET,POST ....
1. Set(name, value) - для сессии
1. Get(name) -  для сессии
1. Delete(name) -  для сессии
1. Close() - для сессии
1. RemoteIP()
1. Body()
1. Download(file)  
1. Redirect(url)


```

func HandlerParamTest(rw *web.RunApi, param web.Param) {
  vv := rw.Form()
  log.Println(vv, param)
  rw.JSON(struct{OK int}{200})
}

func HandlerTest(rw *web.RunApi) {
  vv := rw.Form()
  log.Println(vv)
  rw.JSON(struct{OK int}{200})
}

func HandlerDBTest(rw *web.RunApi, db *sql.Db) {
  vv := rw.Form()
  .....
    rows, err := db.Query(.....)
  .....
  log.Println(vv)
  rw.JSON(struct{OK int}{200})
}

// func HandlerAllTest(db map[string]*AllAll, rw *web.RunApi) {
func HandlerAllTest(rw *web.RunApi, db map[string]*AllAll) {
  vv := rw.Form()
  .....
    db["test"] = .....
  .....
  log.Println(vv)
  rw.JSON(struct{OK int}{200})
}

// Test - test middleware
func Test() bool {
	return true // true - разрешить выполнение роутеров
}
  
// Test2 - test middleware
func Test2(rw *web.RunApi, db *sql.Db) bool {
  .....
  rows, err := db.Query(......)
  .....
	return false // false -запретить выполнение роутеров
}


func main() {
  db := ..... // создать соединение с базой

  mydb := make(map[string]*AllAll)

  my := web.Default()
  my.Use(db)
  my.Use(mydb)

  my.Middle(Test)
  my.Middle(Test2)
  
  my.Get("/test", HandlerTest)
  my.Get("/test1", HandlerDBTest)
  my.Get("/test2", HandlerAllTest)
  my.Get("/test3/:param/:param/", HandlerParamTest)
  v := my.Route('/api/')
  {
    v.Get("list-1", func1)
    v.Get("list-2", func2)
    
  }
  my.Run("0.0.0.0:8888")
}

```  
