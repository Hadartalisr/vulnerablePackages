# VulnerablePackages

A WebAPI application that finds if vulnerable packages are used in the project, <br>
by using Github Security Vulnerabilities GraphQL API.

### Requirements 
  * Golang 1.18 or above
  * Github API personal access token

### How to run the project locally

- Clone the project 
- Perform the following commands from the project's root directory
```
> go build .
> GITHUB_ACCESS_TOKEN=<YOUR_GITHUB_ACCESS_TOKEN> ./vulnerablePackages
```

* note - the personal access token environment variable's name is "GITHUB_ACCESS_TOKEN"
instead of "GITHUB-ACCESS-TOKEN". <br>
See "The Linux Documentation Project" 2nd paragraph in https://tldp.org/LDP/abs/html/gotchas.html
    

### Things that should be modified in a real world application
#### Caching
- Instead of using an internal process memory, I would use an In-memory DB such a redis. 
- Add API that will allow us to flush all the cached vulnerabilities. 
#### Configuration 
- It is true that some configs should be static, but a server config is necessary as well.<br>
E.g., IsVulnerabilitiesCachingEnabled should be a server config.
 