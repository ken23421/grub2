/* efihttp.c - EFI HTTP. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/misc.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>
#include <grub/efi/http.h>
#include <grub/charset.h>

/* EFI-HTTP(S) Boot variables */
grub_efi_http_t *grub_efihttp = NULL;
static grub_efi_boolean_t grub_efihttp_request_callback_done;
static grub_efi_boolean_t grub_efihttp_response_callback_done;
static grub_uint8_t *efihttp_rx_buf;

static void
grub_efihttp_request_callback (grub_efi_event_t event, void *context)
{
  grub_dprintf ("efihttp", "grub_efihttp_request_callback(), event:%p, context:%p\n", event, context);
  grub_efihttp_request_callback_done = 1;
}

static void
grub_efihttp_response_callback (grub_efi_event_t event, void *context)
{
  grub_dprintf ("efihttp", "grub_efihttp_request_callback(), event:%p, context:%p\n", event, context);
  grub_efihttp_response_callback_done = 1;
}

grub_err_t
grub_efihttp_configure (struct grub_net_card *card, const struct grub_net_bootp_packet *bp)
{ 
  grub_efi_guid_t grub_efihttp_sb_guid = GRUB_EFI_HTTP_SERVICE_BINDING_PROTOCOL_GUID;
  grub_efi_guid_t grub_efihttp_guid = GRUB_EFI_HTTP_PROTOCOL_GUID;
  grub_efi_service_binding_t *grub_efihttp_sb = NULL;
  grub_efi_handle_t grub_efihttp_handle = NULL;
  grub_efi_http_config_data_t grub_efihttp_config_data;
  grub_efi_httpv4_access_point_t grub_efihttp_ipv4_node;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  grub_efi_status_t status;

  grub_dprintf ("efihttp", "Enter grub_efihttp_configure()\n");
  
  grub_efihttp_sb = grub_efi_open_protocol (card->efi_handle, &grub_efihttp_sb_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (!grub_efihttp_sb)
  {
      grub_dprintf ("efihttp", "Fail to open the Service Binding protocol!\n");
      return GRUB_ERR_EFI;
  }

  grub_dprintf ("efihttp", "sb->create_child()\n");
  status = efi_call_2 (grub_efihttp_sb->create_child, grub_efihttp_sb, &grub_efihttp_handle);
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Fail to create child! status=%d\n", (int)status);
      return GRUB_ERR_EFI;
  }

  grub_dprintf ("efihttp", "b->handle_protocol()\n");
  status = efi_call_3(b->handle_protocol, grub_efihttp_handle, &grub_efihttp_guid, (void**)&grub_efihttp);
  if (!grub_efihttp || GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Error! Fail to get HTTP protocol! status=%d\n", (int)status);
      return GRUB_ERR_EFI;
  }

  grub_memset (&grub_efihttp_config_data, 0, sizeof(grub_efihttp_config_data));
  grub_efihttp_config_data.http_version = GRUB_EFI_HTTPVERSION11;
  grub_efihttp_config_data.timeout_millisec = 5000;
  grub_efihttp_config_data.local_address_is_ipv6 = 0;
  grub_memset (&grub_efihttp_ipv4_node, 0, sizeof(grub_efihttp_ipv4_node));
  grub_efihttp_ipv4_node.use_default_address = 0;
  grub_memcpy ((void*)grub_efihttp_ipv4_node.local_address, &bp->your_ip, sizeof (bp->your_ip));
  grub_memcpy ((void*)grub_efihttp_ipv4_node.local_subnet, &bp->subnet_mask, sizeof (bp->subnet_mask));
  grub_efihttp_ipv4_node.local_port = 0;
  grub_efihttp_config_data.access_point.ipv4_node = &grub_efihttp_ipv4_node;

  grub_dprintf ("efihttp", "grub_efihttp->configure()\n");
  status = efi_call_2 (grub_efihttp->configure, grub_efihttp, &grub_efihttp_config_data);
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Fail to do configuration! status=%d\n", (int)status);
      return GRUB_ERR_EFI;
  }

  grub_dprintf ("efihttp", "Leave grub_efihttp_configure()\n");

  return GRUB_ERR_NONE;
}
  
grub_err_t
grub_efihttp_open (grub_file_t file, const char *filename)
{
  grub_efi_http_request_data_t request_data;
  grub_efi_http_header_t request_headers[3];
  grub_efi_http_message_t *request_message;
  grub_efi_http_token_t *request_token;
  grub_efi_http_response_data_t response_data;
  grub_efi_http_message_t *response_message;
  grub_efi_http_token_t *response_token;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  grub_efi_status_t status;
  grub_efi_http_status_code_t http_status;
  const char *http = "http://";
  char *url;
  grub_efi_char16_t *usc2_url;
  grub_uint32_t url_len, usc2_url_len;
  grub_uint32_t offset, length, i;

  grub_dprintf ("efihttp", "Enter grub_efihttp_open(), file->name:%s\n", file->name);
  grub_dprintf ("efihttp", "grub_efihttp:%p, grub_efihttp->request:%p\n", grub_efihttp, grub_efihttp->request);

  /* init */
  grub_memset (&request_data, 0, sizeof (grub_efi_http_request_data_t));
  request_message = grub_zalloc (sizeof (grub_efi_http_message_t));
  request_token = grub_zalloc (sizeof (grub_efi_http_token_t));
  grub_memset (&response_data, 0, sizeof (grub_efi_http_response_data_t));
  response_message = grub_zalloc (sizeof (grub_efi_http_message_t));
  response_token = grub_zalloc (sizeof (grub_efi_http_token_t));

  request_data.method = GRUB_EFI_HTTPMETHODGET;

  /* url */
  url_len = grub_strlen (http) + grub_strlen (file->device->net->server) + grub_strlen (file->device->net->name);
  url = grub_malloc ((url_len + 1) * sizeof (url[0]));
  grub_memset (url, 0, url_len);
  grub_strncpy (url, http, grub_strlen(http));
  offset = grub_strlen (http);
  grub_strncpy (url + offset, file->device->net->server, grub_strlen (file->device->net->server));
  offset += grub_strlen (file->device->net->server);
  grub_strncpy (url + offset, file->device->net->name, grub_strlen (file->device->net->name));
  url[url_len] = 0;
  grub_dprintf ("efihttp", "url:%s\n", url);
  usc2_url_len = url_len * GRUB_MAX_UTF16_PER_UTF8;
  usc2_url = grub_malloc ((usc2_url_len + 1) * sizeof (usc2_url[0]));
  usc2_url_len = grub_utf8_to_utf16 (usc2_url, usc2_url_len, (grub_uint8_t *)url, url_len, NULL); /* convert string format from ascii to usc2 */
  usc2_url[usc2_url_len] = 0;
  request_data.url = usc2_url;

  /* headers */
  request_headers[0].field_name = (grub_efi_char8_t*)"Host";
  request_headers[0].field_value = (grub_efi_char8_t*)file->device->net->server;
  request_headers[1].field_name = (grub_efi_char8_t*)"Accept";
  request_headers[1].field_value = (grub_efi_char8_t*)"*/*";
  request_headers[2].field_name = (grub_efi_char8_t*)"User-Agent";
  request_headers[2].field_value = (grub_efi_char8_t*)"UefiHttpBoot/1.0";

  request_message->data.request = &request_data;
  request_message->header_count = 3;
  request_message->headers = request_headers;
  request_message->body_length = 0;
  request_message->body = NULL;

  /* request token */
  request_token->event = NULL;
  request_token->status = GRUB_EFI_NOT_READY;
  request_token->message = request_message;
  grub_efihttp_request_callback_done = 0;
  grub_dprintf ("efihttp", "b->create_event()\n");
  status = efi_call_5 (b->create_event,
                       GRUB_EFI_EVT_NOTIFY_SIGNAL,
                       GRUB_EFI_TPL_CALLBACK,
                       grub_efihttp_request_callback,
                       NULL,
                       &request_token->event);
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Fail to create an event! status=%d\n", (int)status);
      return status;
  }

  grub_dprintf ("efihttp", "grub_efihttp:%p, grub_efihttp->request:%p\n", grub_efihttp, grub_efihttp->request);

  /* make a HTTP request */
  grub_dprintf ("efihttp", "Before grub_efihttp->request(), url:%s\n", url);
  status = efi_call_2 (grub_efihttp->request, grub_efihttp, request_token);
  grub_dprintf ("efihttp", "After grub_efihttp->request()\n");
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Fail to send a request! status=%d\n", (int)status);
      return GRUB_ERR_EFI;
  }
  /* allow the network stack 10 seconds to send the request successfully */
  while (!grub_efihttp_request_callback_done)
  {
      efi_call_1(grub_efihttp->poll, grub_efihttp); // give the http driver more motivation
  }

  response_data.status_code = GRUB_EFI_HTTP_STATUS_UNSUPPORTED_STATUS;
  response_message->data.response = &response_data;
  response_message->header_count = 0; // herader_count will be updated by the HTTP driver on response
  response_message->headers = NULL; // headers will be populated by the driver on response
  /* use zero BodyLength to only receive the response headers */
  response_message->body_length = 0;
  response_message->body = NULL;
  response_token->event = NULL;
  efi_call_5 (b->create_event,
              GRUB_EFI_EVT_NOTIFY_SIGNAL,
              GRUB_EFI_TPL_CALLBACK,
              grub_efihttp_response_callback,
              NULL,
              &response_token->event);
  response_token->status = GRUB_EFI_SUCCESS;
  response_token->message = response_message;

  /* wait for HTTP response */
  grub_efihttp_response_callback_done = 0;
  grub_dprintf ("efihttp", "Before grub_efihttp->response()\n");
  status = efi_call_2 (grub_efihttp->response, grub_efihttp, response_token);
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Fail to receive a response! status=%d\n", (int)status);
      return status;
  }
  while (!grub_efihttp_response_callback_done)
  {
      efi_call_1 (grub_efihttp->poll, grub_efihttp);
  }
  grub_dprintf ("efihttp", "After grub_efihttp->response(), response_message->body_length:%d\n", response_message->body_length);

  /* check the HTTP status code */
  http_status = response_token->message->data.response->status_code;
  grub_dprintf ("efihttp", "http_status=%d\n", (int)http_status);

  /* parse the length of the file from the ContentLength header */
  grub_dprintf ("efihttp", "response_message->header_count:%d\n", response_message->header_count);
  for (length = 0, i = 0; i < response_message->header_count; ++i)
  {
      if (!grub_strcmp((const char*)response_message->headers[i].field_name, "Content-Length"))
      {
          length = grub_strtoul((const char*)response_message->headers[i].field_value, 0, 10);
          break;
      }
  }
  file->size = (grub_off_t)length;
  
  file->not_easily_seekable = 0;
  file->data = (void*)filename;
  file->device->net->offset = 0;
  efihttp_rx_buf = grub_malloc (EFIHTTP_RX_BUF_LEN);
  
  /* release */
  grub_free (request_message);
  grub_free (request_token);
  grub_free (response_message);
  grub_free (response_token);
  
  grub_dprintf ("efihttp", "Leave grub_efihttp_open(), file->size:%d, file->offset:%d\n", (int)file->size, (int)file->offset);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_efihttp_close (grub_file_t file)
{
  grub_efi_status_t status;

  grub_dprintf ("efihttp", "Enter grub_efihttp_close(), file->device->net->name:%s, file->offset:%d\n", file->device->net->name, (int)file->offset);  
  status = efi_call_2 (grub_efihttp->cancel, grub_efihttp, NULL);
  if (GRUB_EFI_SUCCESS != status)
  {
      grub_dprintf ("efihttp", "Error! status=%d\n", (int)status);
      return GRUB_ERR_EFI;
  }
  grub_free (efihttp_rx_buf);
  file->offset = 0;
  file->device->net->offset = 0;
  grub_dprintf ("efihttp", "Leave grub_efihttp_close(), file->device->net->name:%s, file->offset:%d\n", file->device->net->name, (int)file->offset);

  return GRUB_ERR_NONE;
}

grub_ssize_t
grub_efihttp_read (grub_file_t file, char *buf, grub_size_t len)
{
  grub_efi_http_response_data_t response_data;
  grub_efi_http_message_t *response_message;
  grub_efi_http_token_t *response_token;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services; 
  grub_efi_status_t status;
  grub_efi_http_status_code_t http_status;
  char *ptr = buf;
  grub_size_t amount, total = 0;

  grub_dprintf ("efihttp", "Enter grub_efihttp_read(), len:%d\n", (int)len);

  /* zero init */
  grub_memset (&response_data, 0, sizeof (grub_efi_http_response_data_t));
  response_message = grub_zalloc (sizeof (grub_efi_http_message_t));
  response_token = grub_zalloc (sizeof (grub_efi_http_token_t));

  /* receive the data */
  response_message->data.response = &response_data;
  response_message->header_count = 0; // herader_count will be updated by the HTTP driver on response
  response_message->headers = NULL; // headers will be populated by the driver on response
  response_message->body_length = EFIHTTP_RX_BUF_LEN;
  response_message->body = efihttp_rx_buf;
  response_token->event = NULL;
  response_token->status = GRUB_EFI_NOT_READY;
  response_token->message = response_message;
  grub_efihttp_response_callback_done = 0;
  efi_call_5 (b->create_event,
              GRUB_EFI_EVT_NOTIFY_SIGNAL,
              GRUB_EFI_TPL_CALLBACK,
              grub_efihttp_response_callback,
              NULL,
              &response_token->event);

  while (len > 0)
  {
      grub_dprintf ("efihttp", "file->device->net->offset:%d, file->size:%d\n", (int)file->device->net->offset, (int)file->size);
      amount = EFIHTTP_RX_BUF_LEN;
      if (amount > len)
      {
          amount = len;
      }

      response_message->data.response = NULL;
      if (!response_message->headers)
      {
          grub_free(response_message->headers);
      }
      response_message->header_count = 0;
      response_message->headers = NULL;
      response_message->body_length = amount;
      grub_memset(efihttp_rx_buf, 0, amount);

      /* accept another response */
      response_token->status = GRUB_EFI_NOT_READY;
      grub_efihttp_response_callback_done = 0; //false;
      grub_dprintf ("efihttp", "Before grub_efihttp->response(), response_message->body_length:%d\n", response_message->body_length);
      status = efi_call_2 (grub_efihttp->response, grub_efihttp, response_token);
      if (GRUB_EFI_SUCCESS != status)
      {
          grub_dprintf ("efihttp", "Error! status=%d\n", (int)status);
          return 0;
      }

      while (!grub_efihttp_response_callback_done)
      {
          efi_call_1(grub_efihttp->poll, grub_efihttp);
      }

      grub_dprintf ("efihttp", "After grub_efihttp->response(), response_message->body_length:%d, response_token.status:%d\n",
                               response_message->body_length, (int)response_token->status);

      /* check the HTTP status code */
      http_status = response_token->message->data.response->status_code;
      grub_dprintf ("efihttp", "http_status=%d\n", (int)http_status);

      len -= response_message->body_length;
      total += response_message->body_length;
      file->device->net->offset += response_message->body_length;
      if (buf)
      {
        grub_memcpy (ptr, efihttp_rx_buf, response_message->body_length);
        ptr += response_message->body_length;
      }
      grub_dprintf ("efihttp", "len:%d, total:%d, file->device->net->offset:%d\n",
                    (int)len, (int)total, (int)file->device->net->offset);
  }
  
  /* release */
  grub_free (response_message);
  grub_free (response_token);  

  grub_dprintf ("efihttp", "Leave grub_efihttp_read(), file->offset:%d\n", (int)file->offset);

  return total;
}
