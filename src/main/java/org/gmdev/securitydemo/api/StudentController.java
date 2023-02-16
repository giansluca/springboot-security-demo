package org.gmdev.securitydemo.api;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.extern.slf4j.Slf4j;
import org.gmdev.securitydemo.api.model.Student;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@Validated
@RequestMapping("api/v1/students")
public class StudentController {

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/{studentId}")
    @PreAuthorize(value = "hasAnyRole('ROLE_STUDENT', 'ROLE_ADMIN', 'ROLE_MANAGER')")
    public Student getStudent(
            @Parameter(hidden = true) Authentication auth,
            @PathVariable("studentId") Integer studentId) {

        log.info("-- getStudent --");
        return new Student(1, "Bobo");
    }

}
