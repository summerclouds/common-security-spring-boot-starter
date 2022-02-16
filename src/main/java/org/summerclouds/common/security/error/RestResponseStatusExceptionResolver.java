package org.summerclouds.common.security.error;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;
import org.summerclouds.common.core.error.IResult;

// https://www.baeldung.com/exception-handling-for-rest-with-spring
@Component
public class RestResponseStatusExceptionResolver extends AbstractHandlerExceptionResolver {

	@Override
	protected ModelAndView doResolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
			Exception ex) {
		
		try {
			if (ex instanceof IResult) {
				IResult result = (IResult)ex;
				response.sendError(result.getReturnCode(), result.getMessage());
			} else
			if (ex instanceof ResponseStatusException) {
				ResponseStatusException result = (ResponseStatusException)ex;
				response.sendError(result.getRawStatusCode(), result.getMessage());
			} else {
				response.sendError(HttpStatus.BAD_REQUEST.value());
			}
			
		} catch (Throwable t) {
			t.printStackTrace(); //XXX
		}
		
		return new ModelAndView();
	}

}
