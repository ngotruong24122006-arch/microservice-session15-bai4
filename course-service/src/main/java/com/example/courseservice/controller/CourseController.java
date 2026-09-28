package com.example.courseservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final List<String> courses = new ArrayList<>(
            List.of(
                    "Java Spring Boot",
                    "Microservices",
                    "AWS"
            )
    );

    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public List<String> getCourses() {
        return courses;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public String createCourse(
            @RequestBody String course) {

        courses.add(course);

        return "Course created successfully";
    }
}