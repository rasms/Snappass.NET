# Build stage: SDK image with Node.js installed for the frontend build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Install Node.js 20 via NodeSource
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy solution and project files first for layer caching
COPY Snappass.NET.sln ./
COPY Snappass.NET/Snappass.NET.csproj Snappass.NET/

# Restore NuGet packages (Node/npm deps are handled by MSBuild targets during publish)
RUN dotnet restore Snappass.NET/Snappass.NET.csproj

# Copy the rest of the application source
COPY Snappass.NET/ Snappass.NET/

# Publish — MSBuild targets run `npm install` and `npm run build` automatically
RUN dotnet publish Snappass.NET/Snappass.NET.csproj -c Release -o /out --no-self-contained

# Runtime stage: chiseled (no shell, minimal surface area)
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime

WORKDIR /app

COPY --from=build /out .

EXPOSE 8080

ENV ASPNETCORE_URLS=http://+:8080

# The chiseled image already runs as the non-root 'app' user
ENTRYPOINT ["dotnet", "Snappass.NET.dll"]
