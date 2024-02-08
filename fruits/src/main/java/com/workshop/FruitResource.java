package com.workshop;


import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;



@Path("/fruits")
@Produces(MediaType.APPLICATION_JSON)
public class FruitResource {
    private List<Fruit> fruits = Collections.synchronizedList(new ArrayList<>());

    // Add some default fruits
    public FruitResource() {
        fruits.add(new Fruit("Apple", "Winter fruit"));
        fruits.add(new Fruit("Pineapple", "Tropical fruit"));
        fruits.add(new Fruit("Strawberry", "Summer fruit"));
    }

    // The normal get. Should be availbale for the role fruits-read/fruits-write
    @GET
    public List<Fruit> list() {
        return fruits;
    }

    // A get that allow unauthenticated access
    @GET
    @Path("/unauthenticated")
    public List<Fruit> listUnauthenticated() {
        return fruits;
    }

    // A get that allow authenticated access with no role specified
    @GET
    @Path("/authenticated")
    public List<Fruit> listAuthenticated() {
        return fruits;
    }


    // Available for role fruits-read-specific
    @GET
    @Path("/{name}")
    public Response get(@PathParam("name") String name) {
        return fruits.stream()
                .filter(f -> f.name.equalsIgnoreCase(name))
                .findFirst()
                .map(f -> Response.status(Response.Status.OK).entity(f).build())
                .orElse(Response.status(Response.Status.NOT_FOUND).build());
    }

    // Available for role fruits-read-specific with the custom claim 'secret-fruit' specifying what fruit to return
    @GET
    @Path("/secret")
    public Response getSecretFruit() {
        return Response.status(Response.Status.NOT_FOUND).build();
    }


    // Available for role fruits-write
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public List<Fruit> add(Fruit fruit) {
        fruits.add(fruit);
        return fruits;
    }

    // Available for role fruits-delete
    @DELETE
    @Path("/{name}")
    public List<Fruit> delete(@PathParam("name") String name) {
        fruits.removeIf(existingFruit -> existingFruit.name.contentEquals(name));
        return fruits;
    }
}