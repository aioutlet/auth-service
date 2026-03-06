/**
 * Unit tests for ErrorResponse class
 */

import ErrorResponse from '../../../src/core/errors.js';

describe('ErrorResponse', () => {
  it('should create an error with message and status code', () => {
    const error = new ErrorResponse('Test error', 400);
    
    expect(error.message).toBe('Test error');
    expect(error.statusCode).toBe(400);
    expect(error.validationErrors).toBeNull();
  });

  it('should create an error with message, status code, and validation errors', () => {
    const validationErrors = { field: 'email', reason: 'invalid format' };
    const error = new ErrorResponse('Validation failed', 400, validationErrors);
    
    expect(error.message).toBe('Validation failed');
    expect(error.statusCode).toBe(400);
    expect(error.validationErrors).toEqual(validationErrors);
  });

  it('should be an instance of Error', () => {
    const error = new ErrorResponse('Test error', 500);
    
    expect(error).toBeInstanceOf(Error);
  });

  it('should have the correct name', () => {
    const error = new ErrorResponse('Test error', 404);
    
    expect(error.name).toBe('Error');
  });

  it('should handle various status codes', () => {
    const errors = [
      new ErrorResponse('Bad Request', 400),
      new ErrorResponse('Unauthorized', 401),
      new ErrorResponse('Forbidden', 403),
      new ErrorResponse('Not Found', 404),
      new ErrorResponse('Internal Server Error', 500),
    ];
    
    expect(errors[0].statusCode).toBe(400);
    expect(errors[1].statusCode).toBe(401);
    expect(errors[2].statusCode).toBe(403);
    expect(errors[3].statusCode).toBe(404);
    expect(errors[4].statusCode).toBe(500);
  });

  it('should handle complex validation errors objects', () => {
    const validationErrors = {
      fields: [
        { name: 'email', errors: ['required', 'invalid format'] },
        { name: 'password', errors: ['too short'] },
      ],
      timestamp: new Date().toISOString(),
    };
    const error = new ErrorResponse('Validation failed', 400, validationErrors);
    
    expect(error.validationErrors).toEqual(validationErrors);
    expect(error.validationErrors.fields).toHaveLength(2);
  });

  it('should handle null or undefined validation errors', () => {
    const error1 = new ErrorResponse('Test', 400, null);
    const error2 = new ErrorResponse('Test', 400);
    
    expect(error1.validationErrors).toBeNull();
    expect(error2.validationErrors).toBeNull(); // Default parameter is null
  });
});
