# JWT-Authentication
JWT-Authentication (POC)

# Obtener token JWT ir a 

> POST localhost:8080/login


En el body del request definir el objeto json:

>{
  "username" : "batman", 
  "password" : "123"
}

Luego con el token JWT obtenido en el header del response, agregarlo en el header de los request como value del header con key Authorization.

>Bearer <endode_token>

