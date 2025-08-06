# Authorization Server

A reference authorization server using OpenIddict server stack for ASP.NET Core based on this blog series: [Setting up an authorization server with OpenIddict](https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-i-introduction-4jid).

Updated for:

- .NET 8
- OpenIddict v7.0.0

## Local Setup

Use `libman` to restore the packages in `wwwroot/lib`.

Trust HTTPS developement certificate:

```
dotnet dev-certs https --trust
```

Run the project with https profile:

```
dotnet run --launch-profile https
```

Test with `Postman`.
