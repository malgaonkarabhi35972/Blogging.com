import { useState } from 'react';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import ClassicEditor from '@ckeditor/ckeditor5-build-classic';
import { useNavigate, useParams } from 'react-router-dom';
import api from '../services/api';

const PostForm = ({ editMode }) => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      if (editMode) {
        await api.updatePost(id, { title, content });
      } else {
        await api.createPost({ title, content });
      }
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form 
    onSubmit={handleSubmit} 
    className="p-4 rounded shadow-lg bg-light"
  >
    <div className="mb-3">
      <input
        type="text"
        className="form-control"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Post title"
        required
      />
    </div>
  
    <div className="mb-3">
      <CKEditor
        editor={ClassicEditor}
        data={content}
        onChange={(_, editor) => setContent(editor.getData())}
      />
    </div>
  
    <button type="submit" className="btn btn-primary" disabled={loading}>
      {loading ? 'Saving...' : 'Save Post'}
    </button>
  </form>
  
  

    // <form onSubmit={handleSubmit}>
    //   <input
    //     type="text"
    //     value={title}
    //     onChange={(e) => setTitle(e.target.value)}
    //     placeholder="Post title"
    //     required
    //   />
      
    //   <CKEditor
    //     editor={ClassicEditor}
    //     data={content}
    //     onChange={(_, editor) => setContent(editor.getData())}
    //   />
      
    //   <button type="submit" disabled={loading}>
    //     {loading ? 'Saving...' : 'Save Post'}
    //   </button>
    // </form>
  );
};

export default PostForm;