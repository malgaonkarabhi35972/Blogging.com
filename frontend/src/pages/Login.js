// Login.js
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await api.login(formData);
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      navigate('/dashboard');
    } catch (error) {
      alert('Login failed');
    }
  };

  return (
<div
  style={{
    height: '100vh',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'flex-start',   // align items at the top
    paddingTop: '10vh',          // push content down by 10% of viewport height
    backgroundColor: '#f8f9fa',
  }}
>
  <form
    onSubmit={handleSubmit}
    className="p-4 bg-white rounded shadow-lg"
    style={{ boxShadow: '0 0 20px rgba(0, 0, 0, 0.6)', maxWidth: '400px', width: '100%' }}
  >
    <div className="mb-3">
      <input
        type="email"
        value={formData.email}
        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
        required
        placeholder="Email"
        className="form-control"
      />
    </div>

    <div className="mb-4">
      <input
        type="password"
        value={formData.password}
        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
        required
        placeholder="Password"
        className="form-control"
      />
    </div>

    <button type="submit" className="btn btn-dark w-100">
      Login
    </button>
  </form>
</div>



    // <form onSubmit={handleSubmit}>
    //   <input
    //     type="email"
    //     value={formData.email}
    //     onChange={(e) => setFormData({...formData, email: e.target.value})}
    //     required
    //   />
    //   <input
    //     type="password"
    //     value={formData.password}
    //     onChange={(e) => setFormData({...formData, password: e.target.value})}
    //     required
    //   />
    //   <button type="submit">Login</button>
    // </form>
  );
};

export default Login;