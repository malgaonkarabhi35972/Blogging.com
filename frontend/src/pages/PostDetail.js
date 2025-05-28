import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api'; // Axios instance

const PostDetail = () => {
  const { id } = useParams();
  const [post, setPost] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get(`/posts/${id}`)
      .then(res => {
        setPost(res.data);
      })
      .catch(err => {
        console.error(err);
        setError('Post not found or an error occurred.');
      });
  }, [id]);

  if (error) return <div className="container mt-4 alert alert-danger">{error}</div>;
  if (!post) return <div className="container mt-4 text-center">Loading...</div>;

  return (
    <div className="container mt-5">
    <div
      className="card rounded shadow"
      style={{
        boxShadow: '0 8px 20px rgba(0, 0, 0, 0.4)', // dark shadow for entire card
      }}
    >
      {/* Title with black background and white text */}
      <div
        className="card-header"
        style={{
          backgroundColor: '#000000', // black background
          color: '#ffffff',           // white text
        }}
      >
        <h3>{post.title}</h3>
      </div>
  
      {/* Card body with default styling */}
      <div className="card-body">
        {/* Conditionally render image */}
        {post.image && (
          <img
            src={post.image}
            alt={post.title}
            className="img-fluid mb-3"
            style={{ maxHeight: '400px', objectFit: 'cover', width: '100%' }}
          />
        )}
  
        {/* Render HTML content safely */}
        <div dangerouslySetInnerHTML={{ __html: post.content }} />
      </div>
  
      {/* Card footer with muted text */}
      <div className="card-footer text-muted">
        Post ID: {post.id}
      </div>
    </div>
  </div>
  

    // <div className="container mt-5">
    //   <div className="card">
    //     <div className="card-header bg-primary text-white">
    //       <h3>{post.title}</h3>
    //     </div>
    //     <div className="card-body">
    //       {/* Conditionally render image */}
    //       {post.image && (
    //         <img
    //           src={post.image}
    //           alt={post.title}
    //           className="img-fluid mb-3"
    //           style={{ maxHeight: '400px', objectFit: 'cover', width: '100%' }}
    //         />
    //       )}
    //       <p>{post.content}</p>
    //     </div>
    //     <div className="card-footer text-muted">
    //       Post ID: {post.id}
    //     </div>
    //   </div>
    // </div>
  );
};

export default PostDetail;
