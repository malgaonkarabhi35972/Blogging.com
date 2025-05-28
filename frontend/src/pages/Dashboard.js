import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import PostCard from '../components/PostCard';

const Dashboard = () => {
  const [posts, setPosts] = useState([]);

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        const response = await api.getUserPosts();
        setPosts(response.data);
      } catch (error) {
        console.error('Failed to fetch posts', error);
      }
    };
    fetchPosts();
  }, []);

  return (
<div className="container my-4">
  <div className="card shadow-lg" style={{ borderRadius: '1rem', border: 'none' }}>
    <div className="card-body">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1 className="text-primary">Your Posts</h1>
        <Link to="/create-post" className="btn btn-success">
          Create New Post
        </Link>
      </div>
      <div className="row">
        {posts.length > 0 ? (
          posts.map(post => (
            <div key={post.id} className="col-md-6 col-lg-4 mb-4">
              <PostCard post={post} />
            </div>
          ))
        ) : (
          <div className="col-12 text-center">
            <p className="text-muted">No posts available. Create your first post!</p>
          </div>
        )}
      </div>
    </div>
  </div>
</div>




    // <div>
    //   <h1>Your Posts</h1>
    //   <Link to="/create-post">Create New Post</Link>
    //   <div className="posts-grid">
    //     {posts.map(post => (
    //       <PostCard key={post.id} post={post} />
    //     ))}
    //   </div>
    // </div>
  );
};

export default Dashboard;