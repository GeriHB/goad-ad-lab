# Conteinarization

Provide lightweight environment for apps to run, which ensures also that they behave in the same way, regardless of the place that they are deployed.

They are different from **virtual machines** because containers share the host system's kernel. This makes them much more lightweight and efficient.

Containers package an app with all the required tools and settings, so it will run consistently accross different systems without conflict, even though they share the same system's resources.

However, containers isolate apps from the host system and from each other, which provides a barrier and reduces the risk of malicious activities.

But, still they don't offer the same level of isolation as **virtual machines**, and can pose a risk for **privilege escalation** or **container escapes** and gain unauthorized access to the host or other containers.

## Dockers
It's an open-source platform to automate the deployment of apps as self-contained units called.

The container can be started by the following command:

```sh
docker run -p <host port>:<docker port> -d <docker container name>
```

Some docker commands that help on managin containers:

|   Command     |       Description     |
|---------------|-----------------------|
|   docker ps   |   List all running containers   |
| docker stop   |   Stop a running container  |
| docker start  |   Start a container   |
| docker restart|   restart a running container |
| docker rm     |   Remove a container  |
| docker rmi    |   Remove a docker image   |
| docker logs   |   View the logs of a container    |

## Linux Containers - LXC

Is a lightweight virtualization technology that allows multiple isolated Linux systems to run on a single host. 

It uses key resource isolation features, such as **csgroups** and **namespaces**.

The difference between them and **docker** is that:

LXC is focused on creating isolated Linux environments, and Docker on the other hand is more app-focused.

LXC requires more manual setup for building and managing environments, while Docker uses images that include verything needed to run an app (code, libraries, configurations, etc).

Docker is more simple to use, and are generally more secure by default, because of isolation layers like **AppArmor** and **SELinux**.

LXC can be installed by using the following command:

```sh
sudo apt get install lxc lxc-utils
```

And a LXC container can be created (Ubuntu one) with the following:

```sh
sudo lxc-create -n linuxcontainer -t ubuntu
```
