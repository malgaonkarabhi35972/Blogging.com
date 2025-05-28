import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../services/api';

const Register = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverError, setServerError] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    // Clear error when user types
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: ''
      });
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setIsSubmitting(true);
    setServerError('');

    try {
      const { confirmPassword, ...userData } = formData;
      await api.register(userData);
      navigate('/login', { state: { registrationSuccess: true } });
    } catch (error) {
      console.error('Registration error:', error);
      setServerError(
        error.response?.data?.error || 
        'Registration failed. Please try again.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="container d-flex justify-content-center mt-5">
    <div
      className="card shadow rounded"
      style={{ maxWidth: '450px', width: '100%', padding: '20px' }}
    >
      <h2 className="mb-4 text-center">Create an Account</h2>

      {serverError && <div className="alert alert-danger">{serverError}</div>}

      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group mb-3">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            name="username"
            value={formData.username}
            onChange={handleChange}
            className={`form-control ${errors.username ? 'is-invalid' : ''}`}
          />
          {errors.username && (
            <div className="invalid-feedback">{errors.username}</div>
          )}
        </div>

        <div className="form-group mb-3">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className={`form-control ${errors.email ? 'is-invalid' : ''}`}
          />
          {errors.email && (
            <div className="invalid-feedback">{errors.email}</div>
          )}
        </div>

        <div className="form-group mb-3">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className={`form-control ${errors.password ? 'is-invalid' : ''}`}
          />
          {errors.password && (
            <div className="invalid-feedback">{errors.password}</div>
          )}
        </div>

        <div className="form-group mb-4">
          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            className={`form-control ${
              errors.confirmPassword ? 'is-invalid' : ''
            }`}
          />
          {errors.confirmPassword && (
            <div className="invalid-feedback">{errors.confirmPassword}</div>
          )}
        </div>

        <button
          type="submit"
          className="w-100"
          disabled={isSubmitting}
          style={{
            backgroundColor: '#000000', // black background
            color: '#ffffff', // white text
            border: 'none', // no border
            borderRadius: '25px', // rounded corners
            boxShadow: '0 4px 10px rgba(0, 0, 0, 0.7)', // dark shadow
            padding: '10px 0',
            fontWeight: '600',
            cursor: isSubmitting ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.3s ease',
          }}
          onMouseEnter={(e) => {
            if (!isSubmitting) e.currentTarget.style.backgroundColor = '#222222';
          }}
          onMouseLeave={(e) => {
            if (!isSubmitting) e.currentTarget.style.backgroundColor = '#000000';
          }}
        >
          {isSubmitting ? 'Registering...' : 'Register'}
        </button>
      </form>

      <div className="auth-footer mt-3 text-center">
        Already have an account? <Link to="/login">Log in</Link>
      </div>
    </div>
  </div>

    // <div className="auth-container">
    //   <h2>Create an Account</h2>
      
    //   {serverError && <div className="alert error">{serverError}</div>}
      
    //   <form onSubmit={handleSubmit} className="auth-form">
    //     <div className="form-group">
    //       <label htmlFor="username">Username</label>
    //       <input
    //         type="text"
    //         id="username"
    //         name="username"
    //         value={formData.username}
    //         onChange={handleChange}
    //         className={errors.username ? 'error' : ''}
    //       />
    //       {errors.username && <span className="error-message">{errors.username}</span>}
    //     </div>

    //     <div className="form-group">
    //       <label htmlFor="email">Email</label>
    //       <input
    //         type="email"
    //         id="email"
    //         name="email"
    //         value={formData.email}
    //         onChange={handleChange}
    //         className={errors.email ? 'error' : ''}
    //       />
    //       {errors.email && <span className="error-message">{errors.email}</span>}
    //     </div>

    //     <div className="form-group">
    //       <label htmlFor="password">Password</label>
    //       <input
    //         type="password"
    //         id="password"
    //         name="password"
    //         value={formData.password}
    //         onChange={handleChange}
    //         className={errors.password ? 'error' : ''}
    //       />
    //       {errors.password && <span className="error-message">{errors.password}</span>}
    //     </div>

    //     <div className="form-group">
    //       <label htmlFor="confirmPassword">Confirm Password</label>
    //       <input
    //         type="password"
    //         id="confirmPassword"
    //         name="confirmPassword"
    //         value={formData.confirmPassword}
    //         onChange={handleChange}
    //         className={errors.confirmPassword ? 'error' : ''}
    //       />
    //       {errors.confirmPassword && (
    //         <span className="error-message">{errors.confirmPassword}</span>
    //       )}
    //     </div>

    //     <button 
    //       type="submit" 
    //       className="btn-primary"
    //       disabled={isSubmitting}
    //     >
    //       {isSubmitting ? 'Registering...' : 'Register'}
    //     </button>
    //   </form>

    //   <div className="auth-footer">
    //     Already have an account? <Link to="/login">Log in</Link>
    //   </div>
    // </div>
  );
};

export default Register;