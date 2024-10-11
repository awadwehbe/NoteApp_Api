from drf_yasg.utils import swagger_auto_schema

def generate_swagger_auto_schema(operation_summary, operation_description, request_schema, success_response_schema, error_response_schema, tags):
    return swagger_auto_schema(
        operation_summary=operation_summary,
        operation_description=operation_description,
        request_body=request_schema,
        responses={
            201: success_response_schema,
            400: error_response_schema
        },
        tags=tags
    )
