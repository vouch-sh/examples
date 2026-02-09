FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /app

COPY *.csproj ./
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0

WORKDIR /app
COPY --from=build /out .

EXPOSE 3000
ENV ASPNETCORE_URLS=http://+:3000
CMD ["dotnet", "VouchExample.dll"]
