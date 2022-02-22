<template>
  <div class="container">
    <header class="jumbotron">
      <h3>
        <strong>{{ currentUser.username }}</strong> Profile
      </h3>
    </header>
    <p>
      <strong>Id:</strong>
      {{ currentUser.id }}
    </p>
    <strong>Authorities:</strong>
    <ul>
      <li v-for="(role, index) in currentUser.roles" :key="index">
        {{ role }}
      </li>
    </ul>
  </div>
</template>

<script>
import UserService from "../services/user.service";

export default {
  name: "Profile",
  computed: {
    currentUser() {
      return this.$store.state.auth.user;
    },
  },
  mounted() {
    UserService.getUserBoard().then(
      () => {
        if (!this.currentUser) {
          this.$router.push("/login");
        }
      },
      (error) => {
        this.content =
          (error.response && error.response.data) ||
          error.message ||
          error.toString();
        this.$store.dispatch("auth/logout");
        this.$router.push("/login");
      }
    );
  },
};
</script>
