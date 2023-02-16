package org.gmdev.securitydemo.api;

import lombok.extern.slf4j.Slf4j;
import org.gmdev.securitydemo.api.model.Student;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@Validated
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    @ResponseStatus(HttpStatus.OK)
    @GetMapping
    @PreAuthorize(value = "hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')")
    public List<Student> getStudents() {
        log.info("-- getStudents --");
        return List.of(new Student(1, "Jesus"));
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    @PreAuthorize(value = "hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        log.info("-- registerNewStudent --");
    }

    @ResponseStatus(HttpStatus.OK)
    @PutMapping(path = "/{studentId}")
    @PreAuthorize(value = "hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId")Integer studentId, @RequestBody Student student) {
        log.info("-- updateStudent --");
    }

    @ResponseStatus(HttpStatus.OK)
    @DeleteMapping(path = "/{studentId}")
    @PreAuthorize(value = "hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        log.info("-- deleteStudent --");
    }


}
