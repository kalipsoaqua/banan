# banan


*Маленький **web**  framework* 

Функция **Default()** - инстализация  

Функция **Use(context)** - добавить контекст (например базу данных)

Функция **Middle(func)** - добавить функцию middle для обработки до роутинга

Функция **Get(pattern, handler)**,**Post(pattern, handler)**,**Put(pattern, handler)**,**Delete(pattern, handler)** - роутинг по url, pattern - путь по которому надо запустить, тот иkи иной handler

Функция **Run(listen, [cert])** - запуск 

```
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
func Test2() bool {
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
  v := my.Route('/api/')
  {
    v.Get("list-1", func1)
    v.Get("list-2", func2)
    
  }
  my.Run("0.0.0.0:8888")
}

```  
