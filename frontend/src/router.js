import Vue from "vue";
import Router from "vue-router";
import Home from "./views/Home.vue";
import Login from "./views/Login.vue";
import Register from "./views/Register.vue";
import store from "@/store/index.js";

Vue.use(Router);

export const router = new Router({
  mode: "history",
  routes: [
    {
      path: "/home",
      component: Home,
      alias: "/",
    },
    {
      path: "/login",
      component: Login,
    },
    {
      path: "/register",
      component: Register,
    },
    {
      path: "/profile",
      name: "profile",
      component: () => import("./views/Profile.vue"),
    },
    {
      path: "/admin",
      name: "admin",
      component: () => import("./views/BoardAdmin.vue"),
    },
    {
      path: "/mod",
      name: "moderator",
      component: () => import("./views/BoardModerator.vue"),
    },
    {
      path: "/user",
      name: "user",
      component: () => import("./views/BoardUser.vue"),
    },
  ],
});

router.beforeEach((to, from, next) => {
  const publicPages = ["/login", "/register", "/home"];
  const authRequired = !publicPages.includes(to.path);
  const loggedIn = store.state.loggedIn;

  if (authRequired && loggedIn) {
    next("/login");
  } else {
    next();
  }
});
