<template>
    <div
        v-if="showBanner"
        class="bg-bluegray-900 text-gray-100 flex justify-content-between lg:justify-content-center align-items-center flex-wrap"
    >
        <div class="font-bold mr-8">This is an early release</div>
        <div class="align-items-center hidden lg:flex">
            <span class="line-height-3">Please report any bugs, enhancements or features in the</span>
            <a
                v-ripple
                href="https://github.com/mandiant/capa/issues"
                class="flex align-items-center ml-2 mr-8 text-white"
            >
                <span class="no-underline font-bold">Github issues</span>
                <i class="pi pi-github ml-2"></i>
            </a>
        </div>
        <a
            v-ripple
            @click="closeBanner"
            class="flex align-items-center no-underline justify-content-center border-circle text-gray-50 hover:bg-bluegray-700 cursor-pointer transition-colors transition-duration-150"
            style="width: 2rem; height: 2rem"
        >
            <i class="pi pi-times"></i>
        </a>
    </div>
</template>

<script setup>
import { ref, onMounted } from "vue";

const showBanner = ref(true);

onMounted(() => {
    const bannerHidden = localStorage.getItem("bannerHidden");
    if (bannerHidden === "true") {
        showBanner.value = false;
    }
});

const closeBanner = () => {
    showBanner.value = false;
    localStorage.setItem("bannerHidden", "true");
};
</script>
