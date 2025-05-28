import React, { useEffect, useState } from 'react';
import axios from 'axios';

function Home() {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('http://localhost:5000/api/posts')
      .then(response => {
        const data = response.data;
        if (Array.isArray(data)) {
          setPosts(data);
        } else if (data.posts && Array.isArray(data.posts)) {
          setPosts(data.posts);
        } else {
          setPosts([]);
        }
        setLoading(false);
      })
      .catch(err => {
        setError('Failed to load posts. Please try again later.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div className="container my-4"><h2>Loading posts...</h2></div>;
  }

  if (error) {
    return <div className="container my-4"><h2 className="text-danger">{error}</h2></div>;
  }

  return (
    <div className="container my-4">
    <h1 className="mb-4 text-primary">Latest Posts</h1>
    <div className="row">
      {posts.length === 0 ? (
        <p>No posts found.</p>
      ) : (
        posts.map(post => (
          <div key={post.id} className="col-md-4 mb-4"> {/* 3 columns */}
            <div
              className="card h-100"
              style={{
                boxShadow: '0 4px 12px rgba(0,0,0,0.6)', // dark shadow
                borderRadius: '8px', // rounded corners for rectangular feel
                minHeight: '180px'  // adjust height for rectangular shape
              }}
            >
              <div className="card-body d-flex flex-column">
                <h5 className="card-title text-dark">{post.title}</h5>
                <p className="card-text text-secondary flex-grow-1">{post.content}</p>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  </div>
  
  );
}

export default Home;


// import React, { useEffect, useState } from 'react';
// import axios from 'axios';

// function Home() {
//   const [posts, setPosts] = useState([]);

//   useEffect(() => {
//     axios.get('http://localhost:5000/api/posts') // adjust port if needed
//       .then(response => setPosts(response.data))
//       .catch(error => console.error('Error fetching posts:', error));
//   }, []);

//   return (
// <div className="container my-4">
//   <h1 className="mb-4 text-primary">Latest Posts</h1>
//   <div className="row">
//     {posts.map(post => (
//       <div key={post.id} className="col-md-6 mb-4">
//         <div className="card h-100 shadow-sm">
//           <div className="card-body">
//             <h5 className="card-title text-dark">{post.title}</h5>
//             <p className="card-text text-secondary">{post.content}</p>
//           </div>
//         </div>
//       </div>
//     ))}
//   </div>
// </div>


//     // <div>
//     //   <h1>Latest Posts</h1>
//     //   {posts.map(post => (
//     //     <div key={post.id} className="post-card">
//     //       <h2>{post.title}</h2>
//     //       <p>{post.content}</p>
//     //     </div>
//     //   ))}
//     // </div>
//   );
// }

// export default Home;
