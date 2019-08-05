Docker cheats
-------------


````
docker run -t -i -p 8080:8080 --name spid-saml-check spid-saml-check
````

get root access
---------------

````
sudo chmod 666 /var/run/docker.sock

docker container ls
# CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
# bc17d33463fa        spid-saml-check     "/bin/sh -c 'cd spid…"   13 seconds ago      Up 12 seconds       0.0.0.0:8080->8080/tcp   spid-saml-check

sudo docker exec -i -t bc17d33463fa  /bin/bash
````

make our SP reachable
---------------------

add in docker image /etc/hosts an ip:port on the docker bridge interface.
