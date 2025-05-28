import { Link, useNavigate } from 'react-router-dom';

const Navbar = () => {
  const navigate = useNavigate();
  const token = localStorage.getItem('token');

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
    <div className="container">
      <Link className="navbar-brand" to="/">Bloging.com</Link>
      <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
        <span className="navbar-toggler-icon"></span>
      </button>
      <div className="collapse navbar-collapse" id="navbarNav">
        <ul className="navbar-nav ms-auto">
          <li className="nav-item">
            <Link className="nav-link" to="/">Home</Link>
          </li>
          {token ? (
            <>
              <li className="nav-item">
                <Link className="nav-link" to="/dashboard">Dashboard</Link>
              </li>
              <li className="nav-item">
                <Link className="nav-link" to="/create-post">New Post</Link>
              </li>
              <li className="nav-item">
                <button className="btn btn-outline-light ms-2" onClick={handleLogout}>Logout</button>
              </li>
            </>
          ) : (
            <>
              <li className="nav-item">
                <Link className="nav-link" to="/login">Login</Link>
              </li>
              <li className="nav-item">
                <Link className="nav-link" to="/register">Register</Link>
              </li>
            </>
          )}
        </ul>
      </div>
    </div>
  </nav>
  

    // <nav className="navbar navbar-expand-lg navbar-dark bg-primary">
    //   <div className="container">
    //     <Link className="navbar-brand" to="/">Mindbrowser Blog</Link>
    //     <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
    //       <span className="navbar-toggler-icon"></span>
    //     </button>
    //     <div className="collapse navbar-collapse" id="navbarNav">
    //       <ul className="navbar-nav ms-auto">
    //         {token ? (
    //           <>
    //             <li className="nav-item">
    //               <Link className="nav-link" to="/dashboard">Dashboard</Link>
    //             </li>
    //             <li className="nav-item">
    //               <Link className="nav-link" to="/create-post">New Post</Link>
    //             </li>
    //             <li className="nav-item">
    //               <button className="btn btn-outline-light ms-2" onClick={handleLogout}>Logout</button>
    //             </li>
    //           </>
    //         ) : (
    //           <>
    //             <li className="nav-item">
    //               <Link className="nav-link" to="/login">Login</Link>
    //             </li>
    //             <li className="nav-item">
    //               <Link className="nav-link" to="/register">Register</Link>
    //             </li>
    //           </>
    //         )}
    //       </ul>
    //     </div>
    //   </div>
    // </nav>
  );
};

export default Navbar;
