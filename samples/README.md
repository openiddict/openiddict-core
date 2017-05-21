# Run the Sample with the CLI

Clone this repo. Then restore and build OpenIddict-Core. 

    git clone git@github.com:openiddict/openiddict-core.git
    dotnet restore
    dotnet build
    
Start the Mvc Client Sample.

    cd /samples/Mvc.Client
    dotnet restore
    dotnet run --server.urls="http://localhost:53507"
    
In a second command prompt, start the Mvc Server Sample.

    cd /samples/Mvc.Server   
    dotnet restore
    dotnet run --server.urls="http://localhost:54540"
    
For the server to work, you will need either to install SQL Server Express or to use the ASP.NET Core in memory datastore.
