# banan


*Маленький **web**  framework* 

```
func HandlerTest(rw *web.RunApi) {
  vv := rw.Form()
  log.Println(vv)
  rw.JSON(struct{OK int}{200})
}
  

func main() {
  my := web.Default()
  my.Get("/test", HandlerTest)
  my.Run("0.0.0.0:8888")
}

```  
