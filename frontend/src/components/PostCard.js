
import { Link } from 'react-router-dom';

const stripHtml = (html) => {
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = html;
  return tempDiv.textContent || tempDiv.innerText || '';
};

const PostCard = ({ post }) => {
  const previewText = stripHtml(post.content).substring(0, 100);

  return (
    <div className="post-card">
      <h3>{post.title}</h3>
      <p>{previewText}...</p>
      <p>By {post.username}</p>
      <Link to={`/posts/${post.id}`}>Read More</Link>
    </div>
  );
};

export default PostCard;

// import { Link } from 'react-router-dom';

// const PostCard = ({ post }) => {
//   return (
//     <div className="post-card">
//       <h3>{post.title}</h3>
//       <p>{post.content.substring(0, 100)}...</p>
//       <p>By {post.username}</p>
//       <Link to={`/posts/${post.id}`}>Read More</Link>
//     </div>
//   );
// };

// export default PostCard;