# banan


*Маленький **web**  framework* 

Функция **Default()** - инстализация  

Функция **Use(context)** - добавить контекст (на пример базу данных)

Функция **Middle(func)** - добавить функцию middle для обработки до роутинга

Функция **Get(pattern, handler)**,**Post(pattern, handler)**,**Put(pattern, handler)**,**Delete(pattern, handler)** - роутинг по url, pattern - путь по которому надо запустить, тот иkи иной handler

Функция **Run(listen, [cert])** - запуск 

```
func HandlerTest(rw *web.RunApi) {
  vv := rw.Form()
  log.Println(vv)
  rw.JSON(struct{OK int}{200})
}

// Test - test middleware
func Test() bool {
	return false // true - разрешить выполнение роутеров
}
  

func main() {
  my := web.Default()
  my.Middle(Test)
  my.Get("/test", HandlerTest)
  my.Run("0.0.0.0:8888")
}

```  
