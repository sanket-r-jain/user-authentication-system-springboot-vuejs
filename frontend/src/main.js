import Vue from "vue";
import App from "./App.vue";
import axios from "axios";
import { router } from "./router";
import store from "./store";
import VeeValidate from "vee-validate";
import { library } from "@fortawesome/fontawesome-svg-core";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import {
  faHome,
  faUser,
  faUserPlus,
  faSignInAlt,
  faSignOutAlt,
} from "@fortawesome/free-solid-svg-icons";

library.add(faHome, faUser, faUserPlus, faSignInAlt, faSignOutAlt);

Vue.config.productionTip = false;
axios.defaults.withCredentials = true;
Vue.use(VeeValidate);
Vue.component("font-awesome-icon", FontAwesomeIcon);
require("@/assets/main.scss");

new Vue({
  router,
  store,
  render: (h) => h(App),
}).$mount("#app");
