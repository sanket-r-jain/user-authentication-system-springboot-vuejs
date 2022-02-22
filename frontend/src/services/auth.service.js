import axios from "axios";

const API_URL = "http://localhost:8080/api/auth/";

class AuthService {
  async login(user) {
    const response = await axios.post(API_URL + "signin", {
      username: user.username,
      password: user.password,
    });
    return response.data;
  }

  logout() {
    return axios.post(API_URL + "logout");
  }

  register(user) {
    return axios.post(API_URL + "signup", {
      username: user.username,
      email: user.email,
      password: user.password,
      role: user.role,
    });
  }
}

export default new AuthService();
