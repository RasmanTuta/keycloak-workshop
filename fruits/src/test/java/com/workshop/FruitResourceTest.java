package com.workshop;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
public class FruitResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
          .when().get("/fruits")
          .then()
             .statusCode(200)
             .body(is("[{\"name\":\"Apple\",\"description\":\"Winter fruit\"}" +
                     ",{\"name\":\"Pineapple\",\"description\":\"Tropical fruit\"}" +
                     ",{\"name\":\"Strawberry\",\"description\":\"Summer fruit\"}]"));
    }

}