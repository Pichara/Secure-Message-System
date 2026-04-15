# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Clear any NuGet config that might have been copied
RUN rm -f ~/.nuget/NuGet/NuGet.Config

# Copy project file and restore dependencies
COPY SecureMessageBackend.csproj ./
RUN dotnet restore

# Copy all source files
COPY . ./

# Build the project
RUN dotnet publish -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

EXPOSE 8080
ENV PORT=8080

# Copy the published output from the build stage
COPY --from=build /app/publish ./

CMD ["dotnet", "SecureMessageBackend.dll"]
