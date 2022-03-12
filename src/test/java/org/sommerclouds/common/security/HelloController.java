package org.sommerclouds.common.security;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.summerclouds.common.core.error.ErrorRuntimeException;

@RestController
public class HelloController {

	private static final String template = "Hello, %s!";
	private final AtomicLong counter = new AtomicLong();

	@GetMapping("/hello")
	@Secured("ace_rest")
	public Hello greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
		return new Hello(counter.incrementAndGet(), String.format(template, name));
	}

	@GetMapping("/error400")
	public Hello error(@RequestParam(value = "name", defaultValue = "World") String name) {
		throw new ErrorRuntimeException("Test", "arg1");
	}

}
