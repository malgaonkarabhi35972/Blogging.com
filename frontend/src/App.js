import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import AuthRoute from './components/AuthRoute';
import Navbar from './components/Navbar';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import PostList from './pages/PostList';
import PostDetail from './pages/PostDetail';
import PostForm from './pages/PostForm';
import EditPost from './pages/EditPost';
import Home from './components/Home';

function App() {
  return (
    <Router>
      <Navbar />
      <Routes>
        {/* <Route path="/" element={<Home />} /> */}
        <Route path="/home" element={<Home />} />
        <Route path="/" element={<PostList />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        
        {/* Protected routes */}
        <Route path="/dashboard" element={
          <AuthRoute>
            <Dashboard />
          </AuthRoute>
        } />
        <Route path="/create-post" element={
          <AuthRoute>
            <PostForm />
          </AuthRoute>
        } />
        <Route path="/edit-post/:id" element={
          <AuthRoute>
            <PostForm editMode={true} />
          </AuthRoute>
        } />
        <Route path="/posts/:id" element={<PostDetail />} />
        <Route path="/posts/edit/:id" element={<EditPost />} />
      </Routes>
    </Router>
  );
}

export default App;

// function App() {
//   return (
//     <div>
//       <h1>Test Page</h1>
//       <p>If you see this, React is working</p>
//     </div>
//   );
// }
// export default App;