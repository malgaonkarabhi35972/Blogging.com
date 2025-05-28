import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import apiMethods from '../services/api';

const EditPost = () => {
  const { id } = useParams(); // Get post id from URL params
  const navigate = useNavigate();

  const [formData, setFormData] = useState({ title: '', content: '' });
  const [loading, setLoading] = useState(true);

  // Fetch the post data when component mounts
  useEffect(() => {
    const fetchPost = async () => {
      try {
        const response = await apiMethods.getPost(id);
        setFormData({
          title: response.data.title,
          content: response.data.content,
        });
        setLoading(false);
      } catch (error) {
        alert('Failed to load post');
        navigate('/posts'); // Redirect if error
      }
    };
    fetchPost();
  }, [id, navigate]);

  // Handle form input changes
  const handleChange = (e) => {
    setFormData({...formData, [e.target.name]: e.target.value});
  };

  // Handle form submit (update post)
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await apiMethods.updatePost(id, formData);
      alert('Post updated successfully!');
      navigate('/posts'); // Redirect to post list or post detail page
    } catch (error) {
      alert('Failed to update post');
    }
  };

  if (loading) return <p>Loading...</p>;

  return (
    <form 
  onSubmit={handleSubmit} 
  className="p-4 rounded shadow-lg bg-white"
  style={{ boxShadow: '0 0 20px rgba(0, 0, 0, 0.4)' }} // Custom dark shadow
>
  <div className="mb-3">
    <input 
      type="text"
      name="title" 
      value={formData.title} 
      onChange={handleChange} 
      placeholder="Title" 
      required 
      className="form-control"
    />
  </div>

  <div className="mb-3">
    <textarea 
      name="content" 
      value={formData.content} 
      onChange={handleChange} 
      placeholder="Content" 
      required 
      rows="5"
      className="form-control"
    />
  </div>

  <button type="submit" className="btn btn-primary">
    Update Post
  </button>
</form>

    // <form onSubmit={handleSubmit}>
    //   <input 
    //     name="title" 
    //     value={formData.title} 
    //     onChange={handleChange} 
    //     placeholder="Title" 
    //     required 
    //   />
    //   <textarea 
    //     name="content" 
    //     value={formData.content} 
    //     onChange={handleChange} 
    //     placeholder="Content" 
    //     required 
    //   />
    //   <button type="submit">Update Post</button>
    // </form>
  );
};

export default EditPost;
