# Run the Sample

Clone this repo. Then restore and build OpenIddict-Core. 

    git clone git@github.com:openiddict/openiddict-core.git
    dotnet restore
    dotnet build
    
Start the Mvc Client Sample.

    cd /samples/Mvc.Client
    dotnet restore
    dotnet run --server.urls="http://localhost:54540"
    
In a second command prompt, start the Mvc Server Sample

    cd /samples/Mvc.Server   
    dotnet restore`
    dotnet run --server.urls="http://localhost:53507"
