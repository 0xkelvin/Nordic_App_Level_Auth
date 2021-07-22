/* Copyright (c) 2012 Nordic Semiconductor. All Rights Reserved.
 *
 * The information contained herein is property of Nordic Semiconductor ASA.
 * Terms and conditions of usage are described in detail in NORDIC
 * SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */
#include "sdk_config.h"
#if BLE_NUS_ECB_ENABLED
#include "ble_nus_ecb.h"
#include "ble_srv_common.h"
#include "sdk_common.h"
#include "app_error.h"
#include "nrf_delay.h"
#include "ble_hci.h"

#define BLE_UUID_NUS_TX_CHARACTERISTIC   0x0002 /**< The UUID of the TX Characteristic. */
#define BLE_UUID_NUS_RX_CHARACTERISTIC   0x0003 /**< The UUID of the RX Characteristic. */
#define BLE_UUID_NUS_AUTH_CHARACTERISTIC 0x0004 /**< The UUID of the RX Characteristic. */

#define BLE_NUS_ECB_MAX_RX_CHAR_LEN        BLE_NUS_ECB_MAX_DATA_LEN        /**< Maximum length of the RX Characteristic (in bytes). */
#define BLE_NUS_ECB_MAX_TX_CHAR_LEN        BLE_NUS_ECB_MAX_DATA_LEN        /**< Maximum length of the TX Characteristic (in bytes). */
#define BLE_NUS_ECB_MAX_AUTH_CHAR_LEN      SOC_ECB_KEY_LENGTH          /**< Maximum length of the RX Characteristic (in bytes). */

#define APP_FEATURE_NOT_SUPPORTED      (BLE_GATT_STATUS_ATTERR_APP_BEGIN + 2)

#define NUS_ECB_BASE_UUID              {{0x23, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x00, 0x00, 0x40, 0x6E}} /**< Used vendor specific UUID. */

#define RNG_BYTE_WAIT_US               (124UL)

static const uint8_t AUTHORIZED_STR[] = {'A','U','T','H','O','R','I','Z','E','D'};


static void reponse_calc(const uint8_t * p_key, const uint8_t * p_nonce, uint8_t * p_response)
{
    uint32_t           err_code;
    nrf_ecb_hal_data_t m_ecb_data;

    memcpy(&m_ecb_data.key[0],       p_key,   SOC_ECB_KEY_LENGTH);
    memcpy(&m_ecb_data.cleartext[0], p_nonce, SOC_ECB_KEY_LENGTH);

    err_code = sd_ecb_block_encrypt(&m_ecb_data);
    APP_ERROR_CHECK(err_code);

    memcpy(p_response, &m_ecb_data.ciphertext[0], SOC_ECB_KEY_LENGTH);
}


/**
 * @brief Uses the RNG to write a 16-byte nonce to a buffer
 *
 * @param[in]    p_buf    An array of length 16
 */
static void nonce_generate(uint8_t * p_buf)
{
    uint8_t i         = 0;
    uint8_t remaining = SOC_ECB_KEY_LENGTH;

    // The random number pool may not contain enough bytes at the moment so
    // a busy wait may be necessary.
    while(0 != remaining)
    {
        uint32_t err_code;
        uint8_t  available = 0;

        err_code = sd_rand_application_bytes_available_get(&available);
        APP_ERROR_CHECK(err_code);

        available = ((available > remaining) ? remaining : available);
        if (0 != available)
        {
            err_code = sd_rand_application_vector_get((p_buf + i), available);
            APP_ERROR_CHECK(err_code);

            i         += available;
            remaining -= available;
        }

        if (0 != remaining)
        {
            nrf_delay_us(RNG_BYTE_WAIT_US * remaining);
        }
    }
}


static void auth_refresh(ble_nus_ecb_t * p_nus)
{
    p_nus->authorized = false;
    nonce_generate(&p_nus->ecb_nonce[0]);
    reponse_calc(&p_nus->ecb_key[0],
                 &p_nus->ecb_nonce[0],
                 &p_nus->ecb_response[0]);

    printf("ECB NONCE refreshed:\r\n");
    printf("\tECB NONCE:\t\t");
    for (uint32_t i=0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        printf("%02X", p_nus->ecb_nonce[i]);
    }
    printf("\r\n\tExpected response:\t");
    for (uint32_t i=0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        printf("%02X", p_nus->ecb_response[i]);
    }
    printf("\r\n");
}


static uint32_t auth_handle_hvx_send(ble_nus_ecb_t * p_nus, uint8_t * p_string, uint16_t length)
{
    ble_gatts_hvx_params_t hvx_params;

    VERIFY_PARAM_NOT_NULL(p_nus);

    // If the user hasn't enabled notifications then that's OK.
    if ((p_nus->conn_handle == BLE_CONN_HANDLE_INVALID) || (!p_nus->is_auth_notification_enabled))
    {
        return NRF_SUCCESS;
    }

    if (length > BLE_NUS_ECB_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = p_nus->auth_handles.value_handle;
    hvx_params.p_data = p_string;
    hvx_params.p_len  = &length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    return sd_ble_gatts_hvx(p_nus->conn_handle, &hvx_params);
}


/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the S110 SoftDevice.
 *
 * @param[in] p_nus     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_nus_ecb_t * p_nus, ble_evt_t * p_ble_evt)
{
    uint32_t          err_code;
    ble_gatts_value_t gatts_val;

    p_nus->conn_handle = p_ble_evt->evt.gap_evt.conn_handle;

    gatts_val.len     = sizeof(p_nus->ecb_nonce);
    gatts_val.offset  = 0;
    gatts_val.p_value = &p_nus->ecb_nonce[0];

    err_code = sd_ble_gatts_value_set(p_nus->conn_handle,
                                      p_nus->auth_handles.value_handle,
                                      &gatts_val);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for handling the @ref BLE_GAP_EVT_DISCONNECTED event from the S110 SoftDevice.
 *
 * @param[in] p_nus     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_disconnect(ble_nus_ecb_t * p_nus, ble_evt_t * p_ble_evt)
{
    UNUSED_PARAMETER(p_ble_evt);

    p_nus->conn_handle = BLE_CONN_HANDLE_INVALID;

    auth_refresh(p_nus);
}


/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the S110 SoftDevice.
 *
 * @param[in] p_nus     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_nus_ecb_t * p_nus, ble_evt_t * p_ble_evt)
{
    ble_gatts_evt_write_t * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;

    if ((p_evt_write->handle == p_nus->rx_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        if (ble_srv_is_notification_enabled(p_evt_write->data))
        {
            p_nus->is_rx_notification_enabled = true;
        }
        else
        {
            p_nus->is_rx_notification_enabled = false;
        }
    }
    else if ((p_evt_write->handle == p_nus->auth_handles.cccd_handle) &&
             (p_evt_write->len == 2))
    {
        if (ble_srv_is_notification_enabled(p_evt_write->data))
        {
            p_nus->is_auth_notification_enabled = true;
        }
        else
        {
            p_nus->is_auth_notification_enabled = false;
        }
    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}


/**@brief Function for adding RX characteristic.
 *
 * @param[in] p_nus       Nordic UART Service structure.
 * @param[in] p_nus_init  Information needed to initialize the service.
 *
 * @return NRF_SUCCESS on success, otherwise an error code.
 */
static uint32_t rx_char_add(ble_nus_ecb_t * p_nus, const ble_nus_ecb_init_t * p_nus_init)
{
    /**@snippet [Adding proprietary characteristic to S110 SoftDevice] */
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_md_t cccd_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&cccd_md, 0, sizeof(cccd_md));

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);

    cccd_md.vloc = BLE_GATTS_VLOC_STACK;

    memset(&char_md, 0, sizeof(char_md));

    char_md.char_props.notify = 1;
    char_md.p_char_user_desc  = NULL;
    char_md.p_char_pf         = NULL;
    char_md.p_user_desc_md    = NULL;
    char_md.p_cccd_md         = &cccd_md;
    char_md.p_sccd_md         = NULL;

    ble_uuid.type = p_nus->uuid_type;
    ble_uuid.uuid = BLE_UUID_NUS_RX_CHARACTERISTIC;

    memset(&attr_md, 0, sizeof(attr_md));

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);

    attr_md.vloc    = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 0;
    attr_md.vlen    = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = sizeof(uint8_t);
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = BLE_NUS_ECB_MAX_RX_CHAR_LEN;

    return sd_ble_gatts_characteristic_add(p_nus->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_nus->rx_handles);
    /**@snippet [Adding proprietary characteristic to S110 SoftDevice] */
}


/**@brief Function for adding TX characteristic.
 *
 * @param[in] p_nus       Nordic UART Service structure.
 * @param[in] p_nus_init  Information needed to initialize the service.
 *
 * @return NRF_SUCCESS on success, otherwise an error code.
 */
static uint32_t tx_char_add(ble_nus_ecb_t * p_nus, const ble_nus_ecb_init_t * p_nus_init)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&char_md, 0, sizeof(char_md));

    char_md.char_props.write         = 1;
    char_md.char_props.write_wo_resp = 0;
    char_md.p_char_user_desc         = NULL;
    char_md.p_char_pf                = NULL;
    char_md.p_user_desc_md           = NULL;
    char_md.p_cccd_md                = NULL;
    char_md.p_sccd_md                = NULL;

    ble_uuid.type = p_nus->uuid_type;
    ble_uuid.uuid = BLE_UUID_NUS_TX_CHARACTERISTIC;

    memset(&attr_md, 0, sizeof(attr_md));

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);

    attr_md.vloc    = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 1;
    attr_md.vlen    = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = 1;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = BLE_NUS_ECB_MAX_TX_CHAR_LEN;

    return sd_ble_gatts_characteristic_add(p_nus->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_nus->tx_handles);
}


/**@brief Function for adding RX characteristic.
 *
 * @param[in] p_nus       Nordic UART Service structure.
 * @param[in] p_nus_init  Information needed to initialize the service.
 *
 * @return NRF_SUCCESS on success, otherwise an error code.
 */
static uint32_t auth_char_add(ble_nus_ecb_t * p_nus, const ble_nus_ecb_init_t * p_nus_init)
{
    /**@snippet [Adding proprietary characteristic to S110 SoftDevice] */
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;
    ble_gatts_attr_md_t cccd_md;

    memset(&cccd_md, 0, sizeof(cccd_md));

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);

    cccd_md.vloc = BLE_GATTS_VLOC_STACK;

    memset(&char_md, 0, sizeof(char_md));

    char_md.char_props.notify       = 1;
    char_md.char_props.read         = 1;
    char_md.char_props.write        = 1;
    char_md.char_props.write_wo_resp=0;
    char_md.p_char_user_desc        = NULL;
    char_md.p_char_pf               = NULL;
    char_md.p_user_desc_md          = NULL;
    char_md.p_cccd_md               = &cccd_md;
    char_md.p_sccd_md               = NULL;

    ble_uuid.type = p_nus->uuid_type;
    ble_uuid.uuid = BLE_UUID_NUS_AUTH_CHARACTERISTIC;

    memset(&attr_md, 0, sizeof(attr_md));

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);

    attr_md.vloc    = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 1;
    attr_md.vlen    = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = BLE_NUS_ECB_MAX_AUTH_CHAR_LEN;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = BLE_NUS_ECB_MAX_AUTH_CHAR_LEN;

    return sd_ble_gatts_characteristic_add(p_nus->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_nus->auth_handles);
    /**@snippet [Adding proprietary characteristic to S110 SoftDevice] */
}


static void auth_reply_success(ble_evt_t * p_ble_evt, ble_gatts_evt_write_t * p_wr_req)
{
    uint32_t                              err_code;
    ble_gatts_rw_authorize_reply_params_t auth_reply;

    auth_reply.type                     = BLE_GATTS_AUTHORIZE_TYPE_WRITE;
    auth_reply.params.write.gatt_status = BLE_GATT_STATUS_SUCCESS;
    auth_reply.params.write.len         = p_wr_req->len;
    auth_reply.params.write.p_data      = p_wr_req->data;
    auth_reply.params.write.offset      = 0;
    auth_reply.params.write.update      = 1;

    err_code = sd_ble_gatts_rw_authorize_reply(p_ble_evt->evt.gatts_evt.conn_handle, 
                                               &auth_reply); 
    APP_ERROR_CHECK(err_code); 
}


static void auth_reply_error(ble_evt_t * p_ble_evt, uint16_t type)
{
    uint32_t                              err_code;
    ble_gatts_rw_authorize_reply_params_t auth_reply;

    auth_reply.type = type;
    auth_reply.params.write.gatt_status = APP_FEATURE_NOT_SUPPORTED; 

    err_code = sd_ble_gatts_rw_authorize_reply(p_ble_evt->evt.gatts_evt.conn_handle, 
                                               &auth_reply); 
    APP_ERROR_CHECK(err_code); 
}


static void on_write_req(ble_nus_ecb_t * p_nus, ble_evt_t * p_ble_evt)
{
    uint32_t                err_code;
    ble_gatts_evt_write_t * p_wr_req;

    p_wr_req = &p_ble_evt->evt.gatts_evt.params.authorize_request.request.write;

    if (p_wr_req->handle == p_nus->auth_handles.value_handle)
    {
        // This is a write to the AUTH handle.
        if ((SOC_ECB_KEY_LENGTH == p_wr_req->len) &&
            (0 == memcmp(p_wr_req->data,
                         &p_nus->ecb_response[0],
                         SOC_ECB_KEY_LENGTH)))
        {
            ble_gatts_value_t gatts_val;

            p_nus->authorized = true;
            printf("Correct challenge response received.\r\n");

            auth_reply_success(p_ble_evt, p_wr_req);

            // Write a confirmation value to the AUTH handle.
            gatts_val.len     = sizeof(AUTHORIZED_STR);
            gatts_val.offset  = 0;
            gatts_val.p_value = (uint8_t*)&AUTHORIZED_STR[0];

            err_code = sd_ble_gatts_value_set(p_nus->conn_handle,
                                              p_nus->auth_handles.value_handle,
                                              &gatts_val);
            APP_ERROR_CHECK(err_code);

            // Send a notification of the confirmation value.
            err_code = auth_handle_hvx_send(p_nus,
                                            (uint8_t*)&AUTHORIZED_STR[0],
                                            sizeof(AUTHORIZED_STR));
            APP_ERROR_CHECK(err_code);
        }
        else
        {
            printf("Incorrect challenge response.\r\nDisconnecting.\r\n");

            auth_reply_error(p_ble_evt, BLE_GATTS_AUTHORIZE_TYPE_WRITE);
            err_code = sd_ble_gap_disconnect(p_nus->conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
        }
    }
    else if (p_wr_req->handle == p_nus->tx_handles.value_handle)
    {
        // This is received UART data.
        if (p_nus->authorized)
        {
            auth_reply_success(p_ble_evt, p_wr_req);
            p_nus->data_handler(p_nus, p_wr_req->data, p_wr_req->len);
        }
        else
        {
            printf("Data written before authorization.\r\nDisconnecting.\r\n");

            auth_reply_error(p_ble_evt, BLE_GATTS_AUTHORIZE_TYPE_WRITE);
            err_code = sd_ble_gap_disconnect(p_nus->conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
        }
    }
    else
    {
        auth_reply_error(p_ble_evt, BLE_GATTS_AUTHORIZE_TYPE_WRITE);
    }
}


void ble_nus_ecb_on_ble_evt(ble_nus_ecb_t * p_nus, ble_evt_t * p_ble_evt)
{
    if ((p_nus == NULL) || (p_ble_evt == NULL))
    {
        return;
    }

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            on_connect(p_nus, p_ble_evt);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            on_disconnect(p_nus, p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            // This should only happen for the CCCD value.
            on_write(p_nus, p_ble_evt);
            break;

        case BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST: 
        {
            ble_gatts_evt_rw_authorize_request_t  *req;

            req = &p_ble_evt->evt.gatts_evt.params.authorize_request;

            if (BLE_GATTS_AUTHORIZE_TYPE_INVALID != req->type) 
            {
                if ((BLE_GATTS_AUTHORIZE_TYPE_WRITE == req->type) && 
                    (BLE_GATTS_OP_WRITE_REQ == req->request.write.op))
                {
                    on_write_req(p_nus, p_ble_evt);
                }
                else if ((req->request.write.op == BLE_GATTS_OP_PREP_WRITE_REQ)     || 
                         (req->request.write.op == BLE_GATTS_OP_EXEC_WRITE_REQ_NOW) || 
                         (req->request.write.op == BLE_GATTS_OP_EXEC_WRITE_REQ_CANCEL)) 
                {
                    if (req->type == BLE_GATTS_AUTHORIZE_TYPE_WRITE) 
                    { 
                        auth_reply_error(p_ble_evt, BLE_GATTS_AUTHORIZE_TYPE_WRITE);
                    } 
                    else 
                    { 
                        auth_reply_error(p_ble_evt, BLE_GATTS_AUTHORIZE_TYPE_READ);
                    } 
                }
            }
        }

        default:
            // No implementation needed.
            break;
    }
}


uint32_t ble_nus_ecb_init(ble_nus_ecb_t * p_nus, const ble_nus_ecb_init_t * p_nus_init)
{
    uint32_t      err_code;
    ble_uuid_t    ble_uuid;
    ble_uuid128_t nus_base_uuid = NUS_ECB_BASE_UUID;

    VERIFY_PARAM_NOT_NULL(p_nus);
    VERIFY_PARAM_NOT_NULL(p_nus_init);

    // Initialize the service structure.
    p_nus->conn_handle                  = BLE_CONN_HANDLE_INVALID;
    p_nus->data_handler                 = p_nus_init->data_handler;
    p_nus->is_rx_notification_enabled   = false;
    p_nus->is_auth_notification_enabled = false;

    memcpy(&p_nus->ecb_key[0], &p_nus_init->ecb_key[0], sizeof(p_nus->ecb_key));

    /**@snippet [Adding proprietary Service to S110 SoftDevice] */
    // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&nus_base_uuid, &p_nus->uuid_type);
    VERIFY_SUCCESS(err_code);

    ble_uuid.type = p_nus->uuid_type;
    ble_uuid.uuid = BLE_UUID_NUS_SERVICE;

    // Add the service.
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_nus->service_handle);
    /**@snippet [Adding proprietary Service to S110 SoftDevice] */
    VERIFY_SUCCESS(err_code);

    // Add the RX Characteristic.
    err_code = rx_char_add(p_nus, p_nus_init);
    VERIFY_SUCCESS(err_code);

    // Add the TX Characteristic.
    err_code = tx_char_add(p_nus, p_nus_init);
    VERIFY_SUCCESS(err_code);

    // Add the Authentication Characteristic.
    err_code = auth_char_add(p_nus, p_nus_init);
    VERIFY_SUCCESS(err_code);

    auth_refresh(p_nus);

    return NRF_SUCCESS;
}


uint32_t ble_nus_ecb_string_send(ble_nus_ecb_t * p_nus, uint8_t * p_string, uint16_t length)
{
    ble_gatts_hvx_params_t hvx_params;

    VERIFY_PARAM_NOT_NULL(p_nus);

    if ((p_nus->conn_handle == BLE_CONN_HANDLE_INVALID) || (!p_nus->is_rx_notification_enabled))
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (length > BLE_NUS_ECB_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = p_nus->rx_handles.value_handle;
    hvx_params.p_data = p_string;
    hvx_params.p_len  = &length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    return sd_ble_gatts_hvx(p_nus->conn_handle, &hvx_params);
}

#endif //BLE_NUS_ECB_ENABLED
