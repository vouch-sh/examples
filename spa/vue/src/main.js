import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';
import App from './App.vue';
import Callback from './Callback.vue';
import Home from './Home.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Home },
    { path: '/callback', component: Callback },
  ],
});

createApp(App).use(router).mount('#app');
