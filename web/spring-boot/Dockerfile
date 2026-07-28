FROM maven:3.9-eclipse-temurin-25 AS build

WORKDIR /app
COPY pom.xml .
RUN mvn dependency:resolve --no-transfer-progress

COPY src/ src/
RUN mvn package -Dmaven.test.skip=true --no-transfer-progress

FROM eclipse-temurin:25-jre-noble

WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

EXPOSE 3000
CMD ["java", "-jar", "app.jar"]
