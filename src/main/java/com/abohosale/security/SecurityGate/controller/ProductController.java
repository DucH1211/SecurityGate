package com.abohosale.security.SecurityGate.controller;

import com.abohosale.security.SecurityGate.entity.Product;
import com.abohosale.security.SecurityGate.service.ProductService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
@RequestMapping(path = "product")
public class ProductController {
    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('STAFF_MEMBER')")
    public Collection<Product> getProduct(){
        return productService.getAllProducts();
    }

    @DeleteMapping("{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','MANAGER')")
    public void removeProduct(@PathVariable long id){
        productService.deleteProductById(id);
    }
    @PostMapping
    @PreAuthorize("hasAnyAuthority('ASSISTANT_MANAGER','MANAGER','ADMIN')")
    public void addProduct(@RequestBody Product product){
        productService.addProduct(product);
    }

}
