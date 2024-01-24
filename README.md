# versago
Vertical slice architecture in Go

> [!WARNING] 
> Work in progress

# Overview

The focus of vertical slice architecture as [originated](https://www.youtube.com/watch?v=SUiWfhAhgQw) by Jimmy Bogard is to emphasize behavior and abstract away structure. This project aim to help programmers writing backend servers by reducing structural code as much as possible and abstract them into packages. Those packages are:

* dbctx: Simple ORM to reduce repetitive CRUD operations
* httpauth: Middleware for RBAC and JWT Authentication
* httpx: Reduce repetitive HTTP serialization / deserialization, logging, and tracing
