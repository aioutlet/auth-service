import ErrorResponse from '../../src/utils/ErrorResponse.js';

describe('ErrorResponse', () => {
  describe('constructor', () => {
    it('should create an error with message and status code', () => {
      const message = 'Test error message';
      const statusCode = 400;
      
      const error = new ErrorResponse(message, statusCode);
      
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe(message);
      expect(error.statusCode).toBe(statusCode);
    });

    it('should inherit from Error class', () => {
      const error = new ErrorResponse('Test', 500);
      
      expect(error instanceof Error).toBe(true);
      expect(error instanceof ErrorResponse).toBe(true);
    });

    it('should handle different status codes', () => {
      const error400 = new ErrorResponse('Bad Request', 400);
      const error401 = new ErrorResponse('Unauthorized', 401);
      const error404 = new ErrorResponse('Not Found', 404);
      const error500 = new ErrorResponse('Internal Server Error', 500);
      
      expect(error400.statusCode).toBe(400);
      expect(error401.statusCode).toBe(401);
      expect(error404.statusCode).toBe(404);
      expect(error500.statusCode).toBe(500);
    });

    it('should handle empty message', () => {
      const error = new ErrorResponse('', 400);
      
      expect(error.message).toBe('');
      expect(error.statusCode).toBe(400);
    });

    it('should handle special characters in message', () => {
      const message = 'Error with special chars: @#$%^&*()';
      const error = new ErrorResponse(message, 400);
      
      expect(error.message).toBe(message);
    });
  });
});