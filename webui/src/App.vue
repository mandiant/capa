<template>
  <header>
    <div class="wrapper">
      <BannerHeader />
      <NavBar />
    </div>
  </header>
  <RouterView />
</template>

<script setup>
import { RouterView } from 'vue-router'
import NavBar from './components/NavBar.vue'
import BannerHeader from './components/BannerHeader.vue'
</script>
