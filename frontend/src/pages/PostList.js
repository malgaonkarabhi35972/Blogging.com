import { useEffect, useState } from 'react';
import api from '../services/api';
import PostCard from '../components/PostCard';

const PostList = () => {
  const [posts, setPosts] = useState([]);

  useEffect(() => {
    api.getPosts().then(res => setPosts(res.data.posts)); // <--- Fix here
  }, []);
  

  return (
    <div className="post-list">
  {posts.map(post => (
    <div key={post.id} className="mb-4">
      <div className="shadow rounded p-4 bg-white">
        <PostCard post={post} />
      </div>
    </div> 
  ))}
</div>


    // <div className="post-list">
    //   {posts.map(post => (
    //     <PostCard key={post.id} post={post} />
    //   ))}
    // </div>
  );
};

export default PostList;