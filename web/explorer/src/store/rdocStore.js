import { ref } from "vue";

export const rdocStore = {
    data: ref(null),
    setData(newData) {
        this.data.value = newData;
    },
    clearData() {
        this.data.value = null;
    }
};
