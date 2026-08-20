<!--
 * @Author: LPY
 * @Date: 2025-08-26 16:45:08
 * @LastEditors: LPY
 * @LastEditTime: 2025-08-26 17:05:54
 * @FilePath: \glkvm-cloud\web-ui\src\views\device\components\cmdResDetailDialog.vue
 * @Description: 执行命令结果详情弹窗
-->
<template>
    <BaseModal
        :width="672"
        :open="props.open"
        :title="$t('device.commandResponseDetail')"
        destroyOnClose
        @close="emits('update:open', false)"
        :showFooter="false"
    >
        <div class="id">
            <BaseText variant="level2" style="margin-right: 12px;">{{ $t('device.deviceID') }}</BaseText>
            <BaseText>{{ props.res.id }}</BaseText>
        </div>

        <!-- 成功页:命令已执行,展示标准输出(以及有内容时的标准错误输出) -->
        <template v-if="props.type === 'success'">
            <BaseText style="margin: 20px 0 6px;">{{ $t('device.standardOutput') }}</BaseText>
            <ATextarea :value="props.res.stdout" readonly :autoSize="{minRows:1, maxRows: 20}"></ATextarea>

            <template v-if="props.res.stderr">
                <BaseText style="margin: 20px 0 6px;">{{ $t('device.standardErrorOutput') }}</BaseText>
                <ATextarea :value="props.res.stderr" readonly :autoSize="{minRows:1, maxRows: 20}"></ATextarea>
            </template>
        </template>

        <!-- 失败页:平台层未执行成功(离线/超时/格式错),只展示错误信息 -->
        <template v-else>
            <BaseText style="margin: 20px 0 6px;">{{ $t('device.errorMessage') }}</BaseText>
            <ATextarea :value="props.res.msg" readonly :autoSize="{minRows:1, maxRows: 20}"></ATextarea>
        </template>
    </BaseModal>
</template>

<script setup lang="ts">
import BaseModal from '@/components/base/baseModalI18n.vue'

const props = defineProps<{ open: boolean, type: string, res: any }>()

const emits = defineEmits<{
    (e: 'update:open', value: boolean): void;
}>()
</script>

<style scoped lang="scss">
.id {
  display: flex;
  align-items: center;
}
</style>