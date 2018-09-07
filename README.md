# banan


*Маленький **web**  framework* 

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
