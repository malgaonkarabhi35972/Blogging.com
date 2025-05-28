import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:5000/api',
  withCredentials: true
});

// Add auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const apiMethods = {
  // Auth
  login: (data) => api.post('/auth/login', data),
  register: (data) => api.post('/auth/signup', data),

  // Posts
  getPosts: () => api.get('/posts'),
  getPost: (id) => api.get(`/posts/${id}`),
  createPost: (data) => api.post('/posts', data),
  updatePost: (id, data) => api.put(`/posts/${id}`, data),
  deletePost: (id) => api.delete(`/posts/${id}`),
  getUserPosts: () => api.get('/posts/user/me'),
  
  // Expose axios methods directly (optional)
  get: api.get,
  post: api.post,
  put: api.put,
  delete: api.delete
};

export default apiMethods;
